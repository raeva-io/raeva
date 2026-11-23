//! Dependency types a build extension defines, as maven-hpi-plugin defines
//! Jenkins' `executable-war`: a sync reads the extension's artifact
//! handlers and pins its jar, and `--frozen` holds the jar to the pin.

use std::fs;
use std::sync::{Arc, Mutex};

use rv_test_support::http::{Response, StubServer};
use tempfile::TempDir;

use crate::common::{
    assert_success, pom, raeva_command, run_raeva, serve_sha256, sha1_hex, sha256_hex, with_sha256,
};

/// A jar of stored `entries`.
fn jar(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let (mut out, mut directory) = (Vec::new(), Vec::new());
    for (name, contents) in entries {
        let offset = out.len() as u32;
        let sizes = [contents.len() as u32; 2].map(u32::to_le_bytes).concat();
        out.extend_from_slice(b"PK\x03\x04\x14\0\0\0\0\0\0\0\0\0\0\0\0\0");
        out.extend_from_slice(&sizes);
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(contents);
        directory.extend_from_slice(b"PK\x01\x02\x14\0\x14\0\0\0\0\0\0\0\0\0\0\0\0\0");
        directory.extend_from_slice(&sizes);
        directory.extend_from_slice(&(name.len() as u16).to_le_bytes());
        directory.extend_from_slice(&[0; 12]);
        directory.extend_from_slice(&offset.to_le_bytes());
        directory.extend_from_slice(name.as_bytes());
    }
    let start = out.len() as u32;
    let count = (entries.len() as u16).to_le_bytes();
    out.extend_from_slice(&directory);
    out.extend_from_slice(b"PK\x05\x06\0\0\0\0");
    out.extend_from_slice(&[count, count].concat());
    out.extend_from_slice(&(directory.len() as u32).to_le_bytes());
    out.extend_from_slice(&start.to_le_bytes());
    out.extend_from_slice(&[0, 0]);
    out
}

/// An extension jar whose `components.xml` defines `executable-war` as
/// maven-hpi-plugin 3.38 does, and `note` as other bytes of the same jar.
fn extension_jar(note: &[u8]) -> Vec<u8> {
    jar(&[
        (
            "META-INF/plexus/components.xml",
            b"<component-set><components><component>\
              <role>org.apache.maven.artifact.handler.ArtifactHandler</role>\
              <role-hint>executable-war</role-hint>\
              <implementation>org.apache.maven.artifact.handler.DefaultArtifactHandler\
              </implementation><configuration><type>executable-war</type>\
              <extension>war</extension><language>java</language>\
              <addedToClasspath>true</addedToClasspath></configuration>\
              </component></components></component-set>",
        ),
        ("note.txt", note),
    ])
}

/// A repository with `t:ext:1`, whose jar defines nothing, `t:ext:2`, whose
/// jar `ext` gives, metadata that lists both, `t:app:1`, a war that depends
/// on `t:lib:1`, and `t:mid:1`, which depends on `t:app:0` as an
/// `executable-war`.
fn repository(ext: Arc<Mutex<Vec<u8>>>) -> StubServer {
    StubServer::start(move |request| {
        let ext = ext.lock().unwrap().clone();
        with_sha256(request.path.trim_start_matches('/'), files(ext))
    })
}

/// [`repository`]'s files, with `ext` as `t:ext:2`'s jar.
fn files(ext: Vec<u8>) -> Vec<(&'static str, Vec<u8>)> {
    {
        let empty = jar(&[]);
        let plugin = |version: &str| {
            format!(
                "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
                 <artifactId>ext</artifactId><version>{version}</version>\
                 <packaging>maven-plugin</packaging></project>"
            )
        };
        vec![
            ("t/ext/1/ext-1.pom", plugin("1").into_bytes()),
            ("t/ext/1/ext-1.jar", empty.clone()),
            ("t/ext/2/ext-2.pom", plugin("2").into_bytes()),
            ("t/ext/2/ext-2.jar", ext),
            (
                "t/ext/maven-metadata.xml",
                b"<metadata><groupId>t</groupId><artifactId>ext</artifactId><versioning>\
                      <release>2</release><versions><version>1</version><version>2</version>\
                      </versions></versioning></metadata>"
                    .to_vec(),
            ),
            (
                "t/app/1/app-1.pom",
                pom(
                    "app",
                    "<packaging>war</packaging><dependencies><dependency><groupId>t\
                         </groupId><artifactId>lib</artifactId><version>1</version>\
                         </dependency></dependencies>",
                )
                .into_bytes(),
            ),
            ("t/app/1/app-1.war", empty.clone()),
            ("t/app/1/app-1.executable-war", empty.clone()),
            ("t/lib/1/lib-1.pom", pom("lib", "").into_bytes()),
            ("t/lib/1/lib-1.jar", empty),
            (
                "t/mid/1/mid-1.pom",
                pom(
                    "mid",
                    "<dependencies><dependency><groupId>t</groupId><artifactId>app\
                         </artifactId><version>0</version><type>executable-war</type>\
                         </dependency></dependencies>",
                )
                .into_bytes(),
            ),
            ("t/mid/1/mid-1.jar", jar(&[])),
        ]
    }
}

/// A POM and an empty jar at `path` for an artifact outside group `t`,
/// and for `t:plug`, a plugin as those of `org.apache.maven.plugins` are.
fn stand_in(path: &str) -> Option<Vec<u8>> {
    let parts: Vec<&str> = path.split('/').collect();
    let [group @ .., artifact, version, file] = parts.as_slice() else {
        return None;
    };
    let plugin = *artifact == "plug" || group == ["org", "apache", "maven", "plugins"];
    let packaging = if plugin { "maven-plugin" } else { "jar" };
    let served = plugin || group != ["t"];
    match file.strip_prefix(&format!("{artifact}-{version}"))? {
        ".pom" if served => Some(
            format!(
                "<project><modelVersion>4.0.0</modelVersion><groupId>{}</groupId>\
                 <artifactId>{artifact}</artifactId><version>{version}</version>\
                 <packaging>{packaging}</packaging></project>",
                group.join(".")
            )
            .into_bytes(),
        ),
        ".jar" if served => Some(jar(&[])),
        _ => None,
    }
}

/// A plugin's dependency and a processor path take the types the module's
/// build extensions define, as Maven 3.9.12 and 3.10.0 resolve them in the
/// build: `t:app` as `executable-war` is its war, whose dependencies are
/// walked, also where Surefire resolves the plugin's dependency on its own
/// for its JUnit provider. A processor path is the file of its type's
/// extension alone, with no classifier the type implies, so `test-jar` is
/// `t:lib`'s jar.
#[test]
fn plugin_sets_take_the_module_extension_types() {
    let files = files(extension_jar(b"one"));
    let server = StubServer::start(move |request| {
        let path = request.path.trim_start_matches('/');
        serve_sha256(path, |path| {
            let known = files.iter().find(|(name, _)| *name == path);
            known
                .map(|(_, body)| body.clone())
                .or_else(|| stand_in(path))
        })
    });
    let url = format!("http://{}/", server.addr());
    let project = TempDir::new().unwrap();
    let root = project.path();
    let home = home(&url);
    fs::write(root.join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
    let app = |tag: &str| {
        format!(
            "<{tag}><groupId>t</groupId><artifactId>app</artifactId><version>1</version>\
             <type>executable-war</type></{tag}>"
        )
    };
    fs::write(
        root.join("pom.xml"),
        pom(
            "demo",
            &format!(
                "<packaging>pom</packaging><dependencies><dependency><groupId>\
                 org.junit.jupiter</groupId><artifactId>junit-jupiter-api</artifactId>\
                 <version>5.10.0</version><scope>test</scope></dependency><dependency>\
                 <groupId>org.junit.platform</groupId><artifactId>junit-platform-commons\
                 </artifactId><version>1.10.0</version><scope>test</scope></dependency>\
                 </dependencies><build><extensions><extension><groupId>t</groupId>\
                 <artifactId>ext</artifactId><version>2</version></extension></extensions>\
                 <plugins><plugin><groupId>t</groupId><artifactId>plug</artifactId>\
                 <version>1</version><dependencies>{0}</dependencies></plugin><plugin>\
                 <artifactId>maven-surefire-plugin</artifactId><version>3.5.2</version>\
                 <dependencies>{0}</dependencies></plugin>\
                 <plugin><artifactId>maven-compiler-plugin</artifactId><version>3.13.0\
                 </version><configuration><annotationProcessorPaths>{1}<path><groupId>t\
                 </groupId><artifactId>lib</artifactId><version>1</version><type>test-jar\
                 </type></path></annotationProcessorPaths></configuration></plugin>\
                 </plugins></build>",
                app("dependency"),
                app("path")
            ),
        ),
    )
    .unwrap();
    let output = run_raeva(root, home.path(), &["sync"]);
    assert_success(&output, "sync");
    let locked = fs::read_to_string(root.join("raeva.lock")).unwrap();
    let plugin = "coordinates = [\"t:plug:1\"]\nrepo_urls = [\"https://repo.maven.apache.org/maven2/\"]\n\
                  artifacts = \"\"\"\nt:plug:1\\tjar\nt:app:1\\twar\nt:lib:1\\tjar\"\"\"";
    let paths = "\"t:lib:test-jar:1\",\n]\nrepo_urls = [\"https://repo1.maven.org/maven2/\"]\n\
                 artifacts = \"\"\"\nt:app:1\\twar\nt:lib:1\\tjar\"\"\"";
    let provider = "coordinates = [\"t:app:executable-war:1\"]\nrepo_urls = [\"https://repo.maven.apache.org/maven2/\"]\n\
                    artifacts = \"\"\"\nt:app:1\\twar\nt:lib:1\\tjar\"\"\"";
    for set in [plugin, paths, provider] {
        assert!(locked.contains(set), "{set}\n{locked}");
    }
}

/// A home whose settings.xml mirrors everything to `url`.
fn home(url: &str) -> TempDir {
    home_mirroring(url, "*")
}

/// A home whose settings.xml mirrors the repositories `of` names to `url`.
fn home_mirroring(url: &str, of: &str) -> TempDir {
    let home = TempDir::new().unwrap();
    fs::create_dir_all(home.path().join(".m2")).unwrap();
    fs::write(
        home.path().join(".m2/settings.xml"),
        format!(
            "<settings><mirrors><mirror><id>stub</id><url>{url}</url>\
             <mirrorOf>{of}</mirrorOf></mirror></mirrors></settings>"
        ),
    )
    .unwrap();
    home
}

/// `t:app` as `executable-war` resolves to its war, whose dependencies the
/// handler has walked, unlike a `war`'s. The version-less extension takes
/// its version from the metadata, not from plugin management. raeva.lock
/// pins the extension's jar, which an offline `--frozen` reads from the
/// store, and a sync on another machine refuses other bytes for it.
#[test]
fn a_build_extension_defines_a_dependency_type() {
    let ext = Arc::new(Mutex::new(extension_jar(b"one")));
    let server = repository(Arc::clone(&ext));
    let url = format!("http://{}/", server.addr());
    let project = TempDir::new().unwrap();
    let root = project.path();
    let home = home(&url);
    fs::write(
        root.join("pom.xml"),
        pom(
            "demo",
            "<dependencies><dependency><groupId>t</groupId><artifactId>app</artifactId>\
             <version>1</version><type>executable-war</type><scope>test</scope>\
             </dependency></dependencies><build><extensions><extension><groupId>t\
             </groupId><artifactId>ext</artifactId></extension></extensions>\
             <pluginManagement><plugins><plugin><groupId>t</groupId><artifactId>ext\
             </artifactId><version>1</version></plugin></plugins></pluginManagement></build>",
        ),
    )
    .unwrap();
    let sync = |home: &TempDir, args: &[&str]| run_raeva(root, home.path(), args);
    assert_success(&sync(&home, &["sync"]), "sync");
    let lock_path = root.join("raeva.lock");
    let locked = fs::read_to_string(&lock_path).unwrap();
    for line in ["t:app:1\\twar\\ttest", "t:lib:1\\tjar\\t\\ttest"] {
        assert!(locked.contains(line), "{line}: {locked}");
    }
    let pin = format!(
        "extensions = \"t:ext:2\\t{}\"",
        sha256_hex(&extension_jar(b"one"))
    );
    assert!(locked.contains(&pin), "{locked}");
    assert_success(&sync(&home, &["sync", "--frozen"]), "sync --frozen");
    let offline = sync(&home, &["--offline", "sync", "--frozen"]);
    assert_success(&offline, "offline sync --frozen");
    // A `--frozen` sync takes the pinned jar without its checksum file, and
    // an offline one reads it from the store by the pin.
    let pinned = self::home(&url);
    assert_success(&sync(&pinned, &["sync", "--frozen"]), "pinned --frozen");
    let offline = sync(&pinned, &["--offline", "sync", "--frozen"]);
    assert_success(&offline, "offline sync --frozen after a pinned one");

    *ext.lock().unwrap() = extension_jar(b"two");
    let other = self::home(&url);
    let output = sync(&other, &["sync", "--frozen"]);
    assert_eq!(
        output.status.code(),
        Some(7),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read_to_string(&lock_path).unwrap(), locked);
    // A sync that resolves again refuses them too, until `--update`.
    let pom = fs::read_to_string(root.join("pom.xml")).unwrap();
    let edited = pom.replacen("<build>", "<properties><x>1</x></properties><build>", 1);
    fs::write(root.join("pom.xml"), edited).unwrap();
    let output = sync(&other, &["sync"]);
    assert_eq!(
        output.status.code(),
        Some(7),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read_to_string(&lock_path).unwrap(), locked);
    // A conflicted lock keeps the extension's pin through regeneration.
    let hash = locked
        .lines()
        .find(|l| l.starts_with("config_hash"))
        .unwrap();
    let conflicted = locked.replacen(
        hash,
        &format!("<<<<<<< ours\n{hash}\n=======\n{hash}\n>>>>>>> theirs"),
        1,
    );
    fs::write(&lock_path, &conflicted).unwrap();
    let output = sync(&self::home(&url), &["sync"]);
    assert_eq!(
        output.status.code(),
        Some(7),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read_to_string(&lock_path).unwrap(), conflicted);
    fs::write(&lock_path, &locked).unwrap();
    assert_success(&sync(&other, &["sync", "--update"]), "sync --update");
    let updated = fs::read_to_string(&lock_path).unwrap();
    assert!(
        updated.contains(&sha256_hex(&extension_jar(b"two"))),
        "{updated}"
    );
}

/// A plain sync on a home without the build extension jars raeva.lock
/// pins, as on a fresh CI runner, fetches them though the lock is up to
/// date and records no repository for them, so an offline `--frozen` and a
/// seed find them stored. With them stored, it fetches nothing. Offline it
/// fails naming the jar it lacks, and other bytes for one fail it online,
/// leaving the lock as it was.
#[test]
fn a_plain_sync_stores_the_build_extension_jars_the_lock_pins() {
    let ext = Arc::new(Mutex::new(extension_jar(b"one")));
    let server = repository(Arc::clone(&ext));
    let url = format!("http://{}/", server.addr());
    let project = TempDir::new().unwrap();
    let root = project.path();
    fs::write(
        root.join("pom.xml"),
        pom(
            "demo",
            "<dependencies><dependency><groupId>t</groupId><artifactId>app</artifactId>\
             <version>1</version><type>executable-war</type></dependency></dependencies>\
             <build><extensions><extension><groupId>t</groupId><artifactId>ext\
             </artifactId><version>2</version></extension></extensions></build>",
        ),
    )
    .unwrap();
    let run = |home: &TempDir, args: &[&str]| run_raeva(root, home.path(), args);
    assert_success(&run(&home(&url), &["sync"]), "sync");
    let lock_path = root.join("raeva.lock");
    let locked = fs::read_to_string(&lock_path).unwrap();
    let fresh = home(&url);
    let output = run(&fresh, &["--offline", "sync"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(5), "{stderr}");
    assert!(stderr.contains("t:ext:2"), "{stderr}");
    assert_success(&run(&fresh, &["sync"]), "sync on a fresh home");
    assert_eq!(fs::read_to_string(&lock_path).unwrap(), locked);
    let offline = run(&fresh, &["--offline", "sync", "--frozen"]);
    assert_success(&offline, "offline sync --frozen");
    let seed = fresh.path().join("seed");
    let saved = run(&fresh, &["seed", "save", seed.to_str().unwrap()]);
    assert_success(&saved, "seed save");
    let before = server.requests().len();
    assert_success(&run(&fresh, &["sync"]), "sync again");
    assert_eq!(server.requests().len(), before);

    *ext.lock().unwrap() = extension_jar(b"two");
    let output = run(&home(&url), &["sync"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(7), "{stderr}");
    assert!(stderr.contains("t:ext:2"), "{stderr}");
    assert_eq!(fs::read_to_string(&lock_path).unwrap(), locked);
}

/// A build extension jar counts as stored only once a plugin repository
/// served it, as the offline resolution reads it there: another project's
/// restore of it as a dependency from another repository into the same
/// store leaves a plain sync to fetch it, also when this project takes it
/// as a dependency too.
#[test]
fn a_plain_sync_fetches_an_extension_jar_stored_only_as_a_dependency() {
    let other = jar(&[("note.txt", b"other")]);
    let other_pom = "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
                     <artifactId>other</artifactId><version>1</version></project>";
    let mut served = files(extension_jar(b"one"));
    served.push(("t/other/1/other-1.jar", other));
    served.push(("t/other/1/other-1.pom", other_pom.as_bytes().to_vec()));
    let plugins = served.clone();
    let central = StubServer::start(move |request| {
        with_sha256(request.path.trim_start_matches('/'), served.clone())
    });
    let plugins = StubServer::start(move |request| {
        with_sha256(request.path.trim_start_matches('/'), plugins.clone())
    });
    let (url, plugins_url) = (
        format!("http://{}/", central.addr()),
        format!("http://{}/", plugins.addr()),
    );
    let dependencies = "<dependency><groupId>t</groupId><artifactId>other</artifactId>\
                        <version>1</version></dependency><dependency><groupId>t</groupId>\
                        <artifactId>ext</artifactId><version>2</version></dependency>";
    let neighbour = TempDir::new().unwrap();
    let body = format!("<dependencies>{dependencies}</dependencies>");
    fs::write(neighbour.path().join("pom.xml"), pom("neighbour", &body)).unwrap();
    let home = || home_mirroring(&url, "central");
    for own in ["", dependencies] {
        let project = TempDir::new().unwrap();
        let root = project.path();
        fs::write(
            root.join("pom.xml"),
            pom(
                "demo",
                &format!(
                    "<dependencies><dependency><groupId>t</groupId><artifactId>app\
                     </artifactId><version>1</version><type>executable-war</type>\
                     </dependency>{own}</dependencies><build><extensions><extension>\
                     <groupId>t</groupId><artifactId>other</artifactId><version>1</version>\
                     </extension><extension><groupId>t</groupId><artifactId>ext</artifactId>\
                     <version>2</version></extension></extensions></build>\
                     <pluginRepositories><pluginRepository><id>plugins</id><url>{plugins_url}\
                     </url></pluginRepository></pluginRepositories>"
                ),
            ),
        )
        .unwrap();
        let run = |home: &TempDir, args: &[&str]| run_raeva(root, home.path(), args);
        assert_success(&run(&home(), &["sync"]), "sync");
        let shared = home();
        let neighbour = run_raeva(neighbour.path(), shared.path(), &["sync"]);
        assert_success(&neighbour, "sync of another project");
        assert_success(&run(&shared, &["sync"]), "sync on the shared home");
        let before = (central.requests().len(), plugins.requests().len());
        let offline = run(&shared, &["--offline", "sync", "--frozen"]);
        assert_success(&offline, "offline sync --frozen");
        assert_eq!((central.requests().len(), plugins.requests().len()), before);
        let again = run(&shared, &["sync"]);
        assert_success(&again, "sync again");
        let stderr = String::from_utf8_lossy(&again.stderr);
        assert!(!stderr.contains("Resolving"), "{stderr}");
        assert_eq!((central.requests().len(), plugins.requests().len()), before);
    }
}

/// `lock verify` hashes the build extension jar raeva.lock pins, which
/// `--download` puts back as the resolution fetches it.
#[test]
fn lock_verify_checks_the_build_extension_jars() {
    let server = repository(Arc::new(Mutex::new(extension_jar(b"one"))));
    let url = format!("http://{}/", server.addr());
    let project = TempDir::new().unwrap();
    let root = project.path();
    let home = home(&url);
    fs::write(
        root.join("pom.xml"),
        pom(
            "demo",
            "<dependencies><dependency><groupId>t</groupId><artifactId>app</artifactId>\
             <version>1</version><type>executable-war</type></dependency></dependencies>\
             <build><extensions><extension><groupId>t</groupId><artifactId>ext\
             </artifactId><version>2</version></extension></extensions></build>",
        ),
    )
    .unwrap();
    let run = |args: &[&str]| run_raeva(root, home.path(), args);
    assert_success(&run(&["sync"]), "sync");
    assert_success(&run(&["lock", "verify"]), "lock verify");
    let hash = sha256_hex(&extension_jar(b"one"));
    let blobs = home.path().join("store/blobs");
    fs::remove_file(blobs.join(&hash[..2]).join(&hash[2..4]).join(&hash)).unwrap();
    let output = run(&["lock", "verify"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(7), "{stderr}");
    assert!(stderr.contains("t:ext:2"), "{stderr}");
    assert_success(
        &run(&["lock", "verify", "--download"]),
        "lock verify --download",
    );
    assert_success(&run(&["lock", "verify"]), "lock verify after the repair");
}

/// `export-checksums` writes the line of each build extension jar
/// raeva.lock pins, which Maven 3.9.12 and 3.10.0 check as they load the
/// extension.
#[test]
fn export_checksums_pins_the_build_extension_jars() {
    let server = repository(Arc::new(Mutex::new(extension_jar(b"one"))));
    let url = format!("http://{}/", server.addr());
    let project = TempDir::new().unwrap();
    let root = project.path();
    let home = home(&url);
    fs::write(
        root.join("pom.xml"),
        pom(
            "demo",
            "<dependencies><dependency><groupId>t</groupId><artifactId>app</artifactId>\
             <version>1</version><type>executable-war</type></dependency></dependencies>\
             <build><extensions><extension><groupId>t</groupId><artifactId>ext\
             </artifactId><version>2</version></extension></extensions></build>",
        ),
    )
    .unwrap();
    let run = |args: &[&str]| run_raeva(root, home.path(), args);
    assert_success(&run(&["sync"]), "sync");
    assert_success(&run(&["export-checksums"]), "export-checksums");
    let summary = fs::read_to_string(root.join(".mvn/checksums/checksums.sha256")).unwrap();
    let line = format!(
        "{}  t/ext/2/ext-2.jar\n",
        sha256_hex(&extension_jar(b"one"))
    );
    assert!(summary.contains(&line), "{summary}");
}

/// A build extension jar that another module takes as a dependency is the
/// selected module's file to repair, not one from an untrusted origin.
#[test]
fn lock_verify_of_one_module_finds_its_extension_jar_missing() {
    let server = repository(Arc::new(Mutex::new(extension_jar(b"one"))));
    let url = format!("http://{}/", server.addr());
    let project = TempDir::new().unwrap();
    let root = project.path();
    let home = home(&url);
    let reactor = "<packaging>pom</packaging><modules><module>a</module><module>b</module>\
                   </modules>";
    fs::write(root.join("pom.xml"), pom("root", reactor)).unwrap();
    let module = |name: &str, body: &str| {
        fs::create_dir(root.join(name)).unwrap();
        fs::write(root.join(name).join("pom.xml"), pom(name, body)).unwrap();
    };
    module(
        "a",
        "<dependencies><dependency><groupId>t</groupId><artifactId>app</artifactId>\
         <version>1</version><type>executable-war</type></dependency></dependencies>\
         <build><extensions><extension><groupId>t</groupId><artifactId>ext</artifactId>\
         <version>2</version></extension></extensions></build>",
    );
    module(
        "b",
        "<dependencies><dependency><groupId>t</groupId><artifactId>ext</artifactId>\
         <version>2</version></dependency></dependencies>",
    );
    let run = |args: &[&str]| run_raeva(root, home.path(), args);
    assert_success(&run(&["sync"]), "sync");
    let hash = sha256_hex(&extension_jar(b"one"));
    let blobs = home.path().join("store/blobs");
    fs::remove_file(blobs.join(&hash[..2]).join(&hash[2..4]).join(&hash)).unwrap();
    // No resolution repairs it without the reactor's POM.
    fs::remove_file(root.join("pom.xml")).unwrap();
    let output = run(&["lock", "verify", "--download", "--module", "a/pom.xml"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(7), "{stderr}");
    assert!(stderr.contains("missing t:ext:2"), "{stderr}");
}

/// Without plugin locking, raeva.lock pins every build extension jar that
/// reading the handlers of a dependency type read, as Maven loads each
/// one, also an extension that defines no type the module uses. A seed
/// carries them, so a restored home resolves offline, and refuses one
/// whose bytes changed.
#[test]
fn a_seed_carries_the_build_extension_jars() {
    let other = jar(&[("note.txt", b"other")]);
    let mut served = files(extension_jar(b"one"));
    served.push(("t/other/1/other-1.jar", other.clone()));
    let other_pom = "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
                     <artifactId>other</artifactId><version>1</version></project>";
    served.push(("t/other/1/other-1.pom", other_pom.as_bytes().to_vec()));
    let server = StubServer::start(move |request| {
        with_sha256(request.path.trim_start_matches('/'), served.clone())
    });
    let url = format!("http://{}/", server.addr());
    let project = TempDir::new().unwrap();
    let root = project.path();
    let home = home(&url);
    fs::write(
        root.join("pom.xml"),
        pom(
            "demo",
            "<dependencies><dependency><groupId>t</groupId><artifactId>app</artifactId>\
             <version>1</version><type>executable-war</type></dependency></dependencies>\
             <build><extensions><extension><groupId>t</groupId><artifactId>other\
             </artifactId><version>1</version></extension><extension><groupId>t</groupId>\
             <artifactId>ext</artifactId><version>2</version></extension></extensions>\
             </build>",
        ),
    )
    .unwrap();
    let run = |home: &TempDir, args: &[&str]| run_raeva(root, home.path(), args);
    assert_success(&run(&home, &["sync"]), "sync");
    let locked = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(
        locked.contains(&format!("t:other:1\\t{}", sha256_hex(&other))),
        "{locked}"
    );
    let seed = home.path().join("seed");
    let seed = seed.to_str().unwrap();
    assert_success(&run(&home, &["seed", "save", seed]), "seed save");

    let restored = self::home(&url);
    assert_success(&run(&restored, &["seed", "restore", seed]), "seed restore");
    let before = server.requests().len();
    let offline = run(&restored, &["--offline", "sync", "--frozen"]);
    assert_success(&offline, "offline sync --frozen after a restore");
    assert_eq!(server.requests().len(), before);

    let blob = std::path::Path::new(seed)
        .join("blobs")
        .join(sha256_hex(&other));
    fs::remove_file(&blob).unwrap();
    fs::write(&blob, jar(&[("note.txt", b"changed")])).unwrap();
    let output = run(&self::home(&url), &["seed", "restore", seed]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(7), "{stderr}");
    assert!(stderr.contains("t:other:1"), "{stderr}");
}

/// An extension jar whose `components.xml` defines `executable-war` with
/// the file extension `extension`, and nothing else.
fn defining_jar(extension: &str) -> Vec<u8> {
    let xml = format!(
        "<component-set><components><component>\
         <role>org.apache.maven.artifact.handler.ArtifactHandler</role>\
         <role-hint>executable-war</role-hint><configuration><type>executable-war</type>\
         <extension>{extension}</extension><addedToClasspath>true</addedToClasspath>\
         </configuration></component></components></component-set>"
    );
    jar(&[("META-INF/plexus/components.xml", xml.as_bytes())])
}

/// Maven loads a build extension with the set it resolves for it, but the
/// artifacts its core exports, so a handler in a jar the extension depends
/// on types a dependency as one in its own jar does: `t:app` as
/// `executable-war` is its war, as Maven 3.9.12 and 3.10.0 resolve it, and
/// the `maven-artifact` jar in the set, which Maven's core exports, defines
/// nothing. raeva.lock pins each jar of the realm, so a seed carries them
/// and a restored home resolves offline. A realm whose jars define the type
/// differently is refused, as raeva does not follow which one Maven ranks
/// first.
#[test]
fn a_handler_in_a_jar_the_extension_depends_on_types_a_dependency() {
    let carrier = Arc::new(Mutex::new(jar(&[("note.txt", b"carrier")])));
    let handlers = extension_jar(b"one");
    let mut served: Served = (files(jar(&[])).into_iter())
        .map(|(path, bytes)| (path.to_string(), bytes))
        .collect();
    let dependency = |group: &str, artifact: &str, version: &str| {
        format!(
            "<dependency><groupId>{group}</groupId><artifactId>{artifact}</artifactId>\
             <version>{version}</version></dependency>"
        )
    };
    let carrier_pom = pom(
        "carrier",
        &format!(
            "<dependencies>{}{}</dependencies>",
            dependency("t", "handlers", "1"),
            dependency("org.apache.maven", "maven-artifact", "3.9.12")
        ),
    );
    let core = "org/apache/maven/maven-artifact/3.9.12/maven-artifact-3.9.12";
    let core_pom = "<project><modelVersion>4.0.0</modelVersion><groupId>org.apache.maven\
                    </groupId><artifactId>maven-artifact</artifactId><version>3.9.12</version>\
                    </project>";
    served.extend([
        (
            "t/carrier/1/carrier-1.pom".to_string(),
            carrier_pom.into_bytes(),
        ),
        (
            "t/handlers/1/handlers-1.pom".to_string(),
            pom("handlers", "").into_bytes(),
        ),
        ("t/handlers/1/handlers-1.jar".to_string(), handlers.clone()),
        (format!("{core}.pom"), core_pom.as_bytes().to_vec()),
        (format!("{core}.jar"), defining_jar("core")),
    ]);
    let state = Arc::clone(&carrier);
    let server = StubServer::start(move |request| {
        let mut files = served.clone();
        let carrier = state.lock().unwrap().clone();
        files.push(("t/carrier/1/carrier-1.jar".to_string(), carrier));
        with_sha256(request.path.trim_start_matches('/'), files)
    });
    let url = format!("http://{}/", server.addr());
    let project = TempDir::new().unwrap();
    let root = project.path();
    let home = home(&url);
    fs::write(
        root.join("pom.xml"),
        pom(
            "demo",
            "<dependencies><dependency><groupId>t</groupId><artifactId>app</artifactId>\
             <version>1</version><type>executable-war</type></dependency></dependencies>\
             <build><extensions><extension><groupId>t</groupId><artifactId>carrier\
             </artifactId><version>1</version></extension></extensions></build>",
        ),
    )
    .unwrap();
    let run = |home: &TempDir, args: &[&str]| run_raeva(root, home.path(), args);
    assert_success(&run(&home, &["sync"]), "sync");
    let lock_path = root.join("raeva.lock");
    let locked = fs::read_to_string(&lock_path).unwrap();
    let packages = "packages = \"\"\"\nt:app:1\\twar\\tcompile\nt:lib:1\\tjar\"\"\"";
    assert!(locked.contains(packages), "{locked}");
    let pins = format!(
        "extensions = \"\"\"\nt:carrier:1\\t{}\nt:handlers:1\\t{}\"\"\"",
        sha256_hex(&carrier.lock().unwrap()),
        sha256_hex(&handlers)
    );
    assert!(locked.contains(&pins), "{locked}");
    assert_success(&run(&home, &["sync", "--frozen"]), "sync --frozen");
    let seed = home.path().join("seed");
    let seed = seed.to_str().unwrap();
    assert_success(&run(&home, &["seed", "save", seed]), "seed save");
    let restored = self::home(&url);
    assert_success(&run(&restored, &["seed", "restore", seed]), "seed restore");
    let before = server.requests().len();
    let offline = run(&restored, &["--offline", "sync", "--frozen"]);
    assert_success(&offline, "offline sync --frozen after a restore");
    assert_eq!(server.requests().len(), before);

    *carrier.lock().unwrap() = defining_jar("jar");
    fs::remove_file(&lock_path).unwrap();
    let output = run(&self::home(&url), &["sync"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(3), "{stderr}");
    let reason = "dependency type 'executable-war': t:carrier:1 and t:handlers:1 in one \
                  extension realm define it differently";
    assert!(stderr.contains(reason), "{stderr}");
    assert!(!lock_path.exists());
}

/// A `components.xml` handler of `type_` with the `configuration` given.
fn handler_component(type_: &str, configuration: &str) -> String {
    format!(
        "<component><role>org.apache.maven.artifact.handler.ArtifactHandler</role>\
         <role-hint>{type_}</role-hint><implementation>\
         org.apache.maven.artifact.handler.DefaultArtifactHandler</implementation>\
         <configuration><type>{type_}</type>{configuration}</configuration></component>"
    )
}

/// Sync a project that depends on `dependencies`, with the `t:carrier:1`
/// extension, whose jar defines `executable-war` as maven-hpi-plugin does
/// and the handlers of `components`, and which depends on Maven 2.0.11's
/// `maven-core`, whose jar defines `war` as a `zip` of classifier `bar`.
/// `t:x:1` has a file of each type, `t:via:1` takes `t:app:1` as an
/// `executable-war`. A `plugin` other than empty gives the dependencies of
/// the `t:plug:1` plugin, locked with `[plugins] lock`.
fn sync_core_types(
    components: &str,
    dependencies: &str,
    plugin: &str,
) -> (std::process::Output, TempDir) {
    let defining = |components: &str| {
        let xml = format!(
            "<component-set><components>{}{components}</components></component-set>",
            handler_component("executable-war", "<extension>war</extension>")
        );
        jar(&[("META-INF/plexus/components.xml", xml.as_bytes())])
    };
    let core = "org/apache/maven/maven-core/2.0.11/maven-core-2.0.11";
    let core_pom = "<project><modelVersion>4.0.0</modelVersion><groupId>org.apache.maven\
                    </groupId><artifactId>maven-core</artifactId><version>2.0.11</version>\
                    </project>";
    let war = handler_component(
        "war",
        "<extension>zip</extension><classifier>bar</classifier>",
    );
    let mut served: Served = (files(jar(&[])).into_iter())
        .map(|(path, bytes)| (path.to_string(), bytes))
        .collect();
    served.extend([
        (
            "t/carrier/1/carrier-1.pom".to_string(),
            pom(
                "carrier",
                "<dependencies><dependency><groupId>org.apache.maven</groupId>\
                 <artifactId>maven-core</artifactId><version>2.0.11</version></dependency>\
                 </dependencies>",
            )
            .into_bytes(),
        ),
        (
            "t/carrier/1/carrier-1.jar".to_string(),
            defining(components),
        ),
        (format!("{core}.pom"), core_pom.as_bytes().to_vec()),
        (
            format!("{core}.jar"),
            jar(&[(
                "META-INF/plexus/components.xml",
                format!("<component-set><components>{war}</components></component-set>").as_bytes(),
            )]),
        ),
        (
            "t/via/1/via-1.pom".to_string(),
            pom(
                "via",
                "<dependencies><dependency><groupId>t</groupId><artifactId>app</artifactId>\
                 <version>1</version><type>executable-war</type></dependency></dependencies>",
            )
            .into_bytes(),
        ),
        ("t/via/1/via-1.jar".to_string(), jar(&[])),
        ("t/x/1/x-1.pom".to_string(), pom("x", "").into_bytes()),
    ]);
    for file in [
        "x-1.jar",
        "x-1.war",
        "x-1.zip",
        "x-1-bar.zip",
        "x-1-tests.jar",
    ] {
        served.push((format!("t/x/1/{file}"), file.as_bytes().to_vec()));
    }
    let (server, _) = served_repository(served);
    let url = format!("http://{}/", server.addr());
    let project = TempDir::new().unwrap();
    let (packaging, plugins) = if plugin.is_empty() {
        ("", String::new())
    } else {
        fs::write(
            project.path().join("raeva.toml"),
            "[plugins]\nlock = true\n",
        )
        .unwrap();
        let plugins = format!(
            "<plugins><plugin><groupId>t</groupId><artifactId>plug</artifactId>\
             <version>1</version><dependencies>{plugin}</dependencies></plugin></plugins>"
        );
        ("<packaging>pom</packaging>", plugins)
    };
    fs::write(
        project.path().join("pom.xml"),
        pom(
            "demo",
            &format!(
                "{packaging}<dependencies>{dependencies}</dependencies><build><extensions>\
                 <extension><groupId>t</groupId><artifactId>carrier</artifactId>\
                 <version>1</version></extension></extensions>{plugins}</build>"
            ),
        ),
    )
    .unwrap();
    let output = run_raeva(project.path(), home(&url).path(), &["sync"]);
    (output, project)
}

/// A `t` dependency of `artifact` as `type_`, or of the default type.
fn typed(artifact: &str, type_: Option<&str>) -> String {
    let type_ = type_.map_or_else(String::new, |type_| format!("<type>{type_}</type>"));
    format!(
        "<dependency><groupId>t</groupId><artifactId>{artifact}</artifactId>\
         <version>1</version>{type_}</dependency>"
    )
}

/// Where a module's resolution reads its extensions' handlers, for a type
/// Maven's core does not define, one that defines a core type other than
/// the core is refused (exit 3) for a dependency of that type, met before
/// the realm was read or since: Maven takes the extension's handler for a
/// type the build did not look up before, so raeva cannot tell which one
/// it takes. A dependency without a type is a `jar`.
#[test]
fn a_realm_that_defines_a_core_type_otherwise_is_refused() {
    let war = handler_component(
        "war",
        "<extension>zip</extension><classifier>bar</classifier>",
    );
    let jar = handler_component("jar", "<extension>zip</extension>");
    let cases = [
        (
            &war,
            typed("x", Some("war")) + &typed("app", Some("executable-war")),
            "war",
        ),
        (&war, typed("x", Some("war")) + &typed("via", None), "war"),
        (
            &jar,
            typed("x", None) + &typed("app", Some("executable-war")),
            "jar",
        ),
    ];
    for (components, dependencies, type_) in cases {
        let (output, project) = sync_core_types(components, &dependencies, "");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(3), "{dependencies}\n{stderr}");
        let reason = format!(
            "While resolving the build-extension t:carrier:1:\n\nunsupported model: raeva \
             cannot read the handler of dependency type '{type_}': a build extension defines \
             it other than Maven's core, and Maven may take either handler"
        );
        assert!(stderr.contains(&reason), "{dependencies}\n{stderr}");
        assert!(!project.path().join("raeva.lock").exists());
    }
}

/// With `[plugins] lock`, which reads each build extension's realm, a
/// plugin's dependency of a core type the realm defines otherwise is refused
/// (exit 3) too, though the module's resolution does not read the realm.
#[test]
fn plugin_locking_refuses_a_core_type_a_realm_defines_otherwise() {
    let war = handler_component(
        "war",
        "<extension>zip</extension><classifier>bar</classifier>",
    );
    let (output, project) = sync_core_types(&war, "", &typed("x", Some("war")));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(3), "{stderr}");
    let reason = "While resolving the plugin t:plug:1:\n\nWhile resolving the build-extension \
                  t:carrier:1:\n\nunsupported model: raeva cannot read the handler of \
                  dependency type 'war': a build extension defines it other than Maven's core, \
                  and Maven may take either handler";
    assert!(stderr.contains(reason), "{stderr}");
    assert!(!project.path().join("raeva.lock").exists());
}

/// A realm that defines a core type as the core does, as maven-jar-plugin
/// 3.5.1 defines `jar` and `test-jar`, locks it with the core's handler, and
/// the `war` of the `maven-core` jar in the realm's set counts for nothing,
/// as Maven's core exports it.
#[test]
fn a_realm_that_defines_a_core_type_as_the_core_does_locks() {
    let components = handler_component(
        "jar",
        "<language>java</language><addedToClasspath>true</addedToClasspath>",
    ) + &handler_component(
        "test-jar",
        "<classifier>tests</classifier><extension>jar</extension><packaging>jar</packaging>\
         <language>java</language><addedToClasspath>true</addedToClasspath>",
    );
    let dependencies = typed("x", None)
        + &typed("x", Some("test-jar"))
        + &typed("x", Some("war"))
        + &typed("app", Some("executable-war"));
    let (output, project) = sync_core_types(&components, &dependencies, "");
    assert_success(&output, "sync");
    let locked = fs::read_to_string(project.path().join("raeva.lock")).unwrap();
    for package in [
        "t:x:1\\tjar",
        "t:x:1\\tjar:tests",
        "t:x:1\\twar",
        "t:app:1\\twar",
    ] {
        assert!(locked.contains(package), "{package}\n{locked}");
    }
    assert!(!locked.contains("zip"), "{locked}");
}

/// The class file of `x.Base`, a `DefaultArtifactHandler` of the type
/// `executable-war` whose no-argument constructor sets
/// `includesDependencies` to `includes`, as javac compiles it.
fn base_class(includes: bool) -> Vec<u8> {
    let utf8 = |text: &str| {
        [
            &[1][..],
            &(text.len() as u16).to_be_bytes(),
            text.as_bytes(),
        ]
        .concat()
    };
    let pool = [
        utf8("x/Base"),
        vec![7, 0, 1],
        utf8("org/apache/maven/artifact/handler/DefaultArtifactHandler"),
        vec![7, 0, 3],
        utf8("<init>"),
        utf8("(Ljava/lang/String;)V"),
        vec![12, 0, 5, 0, 6],
        vec![10, 0, 4, 0, 7],
        utf8("executable-war"),
        vec![8, 0, 9],
        utf8("setIncludesDependencies"),
        utf8("(Z)V"),
        vec![12, 0, 11, 0, 12],
        vec![10, 0, 2, 0, 13],
        utf8("Code"),
        utf8("()V"),
    ]
    .concat();
    let flag = if includes { 0x04 } else { 0x03 };
    let code = [0x2a, 0x13, 0, 10, 0xb7, 0, 8, 0x2a, flag, 0xb6, 0, 14, 0xb1];
    let mut out = vec![0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 52, 0, 17];
    out.extend_from_slice(&pool);
    out.extend_from_slice(&[0, 0x21, 0, 2, 0, 4, 0, 0, 0, 0, 0, 1]);
    out.extend_from_slice(&[0, 1, 0, 5, 0, 16, 0, 1, 0, 15]);
    out.extend_from_slice(&(12 + code.len() as u32).to_be_bytes());
    out.extend_from_slice(&[0, 2, 0, 1]);
    out.extend_from_slice(&(code.len() as u32).to_be_bytes());
    out.extend_from_slice(&code);
    out.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    out
}

/// A handler class that two jars of an extension's realm hold with other
/// bytes is refused, as Maven's realm loads the one of the first jar on its
/// class path and raeva does not follow that order: the sync fails (exit
/// 3) and writes no lock. Jars that hold the same bytes lock its type.
#[test]
fn a_realm_refuses_a_handler_class_its_jars_define_differently() {
    let xml = b"<component-set><components><component>\
                <role>org.apache.maven.artifact.handler.ArtifactHandler</role>\
                <role-hint>executable-war</role-hint><implementation>x.Base</implementation>\
                <configuration><extension>war</extension></configuration>\
                </component></components></component-set>";
    let carrier_pom = pom(
        "carrier",
        "<dependencies><dependency><groupId>t</groupId><artifactId>za</artifactId>\
         <version>1</version></dependency><dependency><groupId>t</groupId>\
         <artifactId>ab</artifactId><version>1</version></dependency></dependencies>",
    );
    let realm = |ab: bool| {
        let mut served: Served = (files(jar(&[])).into_iter())
            .map(|(path, bytes)| (path.to_string(), bytes))
            .collect();
        served.extend([
            (
                "t/carrier/1/carrier-1.pom".to_string(),
                carrier_pom.clone().into_bytes(),
            ),
            (
                "t/carrier/1/carrier-1.jar".to_string(),
                jar(&[("META-INF/plexus/components.xml", xml)]),
            ),
            ("t/za/1/za-1.pom".to_string(), pom("za", "").into_bytes()),
            (
                "t/za/1/za-1.jar".to_string(),
                jar(&[("x/Base.class", &base_class(true))]),
            ),
            ("t/ab/1/ab-1.pom".to_string(), pom("ab", "").into_bytes()),
            (
                "t/ab/1/ab-1.jar".to_string(),
                jar(&[("x/Base.class", &base_class(ab))]),
            ),
        ]);
        served
    };
    let (server, served) = served_repository(realm(true));
    let url = format!("http://{}/", server.addr());
    let project = TempDir::new().unwrap();
    let root = project.path();
    fs::write(
        root.join("pom.xml"),
        pom(
            "demo",
            "<dependencies><dependency><groupId>t</groupId><artifactId>app</artifactId>\
             <version>1</version><type>executable-war</type></dependency></dependencies>\
             <build><extensions><extension><groupId>t</groupId><artifactId>carrier\
             </artifactId><version>1</version></extension></extensions></build>",
        ),
    )
    .unwrap();
    assert_success(&run_raeva(root, home(&url).path(), &["sync"]), "sync");
    let lock_path = root.join("raeva.lock");
    let locked = fs::read_to_string(&lock_path).unwrap();
    assert!(locked.contains("t:app:1\\twar\\tcompile\""), "{locked}");
    fs::remove_file(&lock_path).unwrap();

    *served.lock().unwrap() = realm(false);
    let output = run_raeva(root, home(&url).path(), &["sync"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(3), "{stderr}");
    let reason = "dependency type 'executable-war': t:ab:1 and t:za:1 in one extension \
                  realm define class x.Base differently";
    assert!(stderr.contains(reason), "{stderr}");
    assert!(!lock_path.exists());
}

/// A classified jar of an extension's realm, as sisu-guice's `no_aop` one
/// in maven-bundle-plugin's, is pinned with its classifier like the others,
/// so a seed carries it and a restored home resolves offline.
#[test]
fn a_seed_carries_a_classified_jar_of_an_extension_realm() {
    let handlers = extension_jar(b"classified");
    let mut served: Served = (files(jar(&[])).into_iter())
        .map(|(path, bytes)| (path.to_string(), bytes))
        .collect();
    let carrier_pom = pom(
        "carrier",
        "<dependencies><dependency><groupId>t</groupId><artifactId>handlers</artifactId>\
         <version>1</version><classifier>no_aop</classifier></dependency></dependencies>",
    );
    let carrier = jar(&[("note.txt", b"carrier")]);
    served.extend([
        (
            "t/carrier/1/carrier-1.pom".to_string(),
            carrier_pom.into_bytes(),
        ),
        ("t/carrier/1/carrier-1.jar".to_string(), carrier.clone()),
        (
            "t/handlers/1/handlers-1.pom".to_string(),
            pom("handlers", "").into_bytes(),
        ),
        (
            "t/handlers/1/handlers-1-no_aop.jar".to_string(),
            handlers.clone(),
        ),
    ]);
    let server = StubServer::start(move |request| {
        with_sha256(request.path.trim_start_matches('/'), served.clone())
    });
    let url = format!("http://{}/", server.addr());
    let project = TempDir::new().unwrap();
    let root = project.path();
    let home = home(&url);
    fs::write(
        root.join("pom.xml"),
        pom(
            "demo",
            "<dependencies><dependency><groupId>t</groupId><artifactId>app</artifactId>\
             <version>1</version><type>executable-war</type></dependency></dependencies>\
             <build><extensions><extension><groupId>t</groupId><artifactId>carrier\
             </artifactId><version>1</version></extension></extensions></build>",
        ),
    )
    .unwrap();
    let run = |home: &TempDir, args: &[&str]| run_raeva(root, home.path(), args);
    assert_success(&run(&home, &["sync"]), "sync");
    let locked = fs::read_to_string(root.join("raeva.lock")).unwrap();
    let packages = "packages = \"\"\"\nt:app:1\\twar\\tcompile\nt:lib:1\\tjar\"\"\"";
    assert!(locked.contains(packages), "{locked}");
    let pins = format!(
        "extensions = \"\"\"\nt:carrier:1\\t{}\nt:handlers:1:no_aop\\t{}\"\"\"",
        sha256_hex(&carrier),
        sha256_hex(&handlers)
    );
    assert!(locked.contains(&pins), "{locked}");
    let seed = home.path().join("seed");
    let seed = seed.to_str().unwrap();
    assert_success(&run(&home, &["seed", "save", seed]), "seed save");
    let restored = self::home(&url);
    assert_success(&run(&restored, &["seed", "restore", seed]), "seed restore");
    let before = server.requests().len();
    let offline = run(&restored, &["--offline", "sync", "--frozen"]);
    assert_success(&offline, "offline sync --frozen after a restore");
    assert_eq!(server.requests().len(), before);
}

/// A range in an extension's realm stays at the jar raeva.lock pins after
/// a newer version is published: `--frozen` replays it as it replays a
/// dependency's range, so it and a plain sync agree that the lock is up to
/// date, and only `--update` takes the newer jar.
#[test]
fn frozen_holds_a_range_in_an_extension_realm() {
    let listed = |versions: &[&str]| -> Served {
        let mut served: Served = (files(jar(&[])).into_iter())
            .map(|(path, bytes)| (path.to_string(), bytes))
            .collect();
        let carrier = pom(
            "carrier",
            "<dependencies><dependency><groupId>t</groupId><artifactId>handlers\
             </artifactId><version>[1,)</version></dependency></dependencies>",
        );
        served.push(("t/carrier/1/carrier-1.pom".into(), carrier.into_bytes()));
        served.push(("t/carrier/1/carrier-1.jar".into(), jar(&[])));
        for version in versions {
            let handlers = pom("handlers", "").replace(">1<", &format!(">{version}<"));
            let path = format!("t/handlers/{version}/handlers-{version}");
            served.push((format!("{path}.pom"), handlers.into_bytes()));
            served.push((format!("{path}.jar"), extension_jar(version.as_bytes())));
        }
        let listing: String = (versions.iter())
            .map(|version| format!("<version>{version}</version>"))
            .collect();
        let metadata = format!(
            "<metadata><groupId>t</groupId><artifactId>handlers</artifactId><versioning>\
             <versions>{listing}</versions></versioning></metadata>"
        );
        served.push((
            "t/handlers/maven-metadata.xml".into(),
            metadata.into_bytes(),
        ));
        served
    };
    let (server, state) = served_repository(listed(&["1"]));
    let url = format!("http://{}/", server.addr());
    let project = TempDir::new().unwrap();
    let root = project.path();
    fs::write(
        root.join("pom.xml"),
        pom(
            "demo",
            "<dependencies><dependency><groupId>t</groupId><artifactId>app</artifactId>\
             <version>1</version><type>executable-war</type></dependency></dependencies>\
             <build><extensions><extension><groupId>t</groupId><artifactId>carrier\
             </artifactId><version>1</version></extension></extensions></build>",
        ),
    )
    .unwrap();
    // A home of its own for each run, as one reads the listing once a day.
    let sync = |args: &[&str]| run_raeva(root, home(&url).path(), args);
    assert_success(&sync(&["sync"]), "sync");
    let lock_path = root.join("raeva.lock");
    let locked = fs::read_to_string(&lock_path).unwrap();
    let pin = |version: &str| {
        format!(
            "t:handlers:{version}\\t{}",
            sha256_hex(&extension_jar(version.as_bytes()))
        )
    };
    assert!(locked.contains(&pin("1")), "{locked}");
    *state.lock().unwrap() = listed(&["1", "2"]);
    for args in [&["sync", "--frozen"][..], &["sync"], &["sync", "--frozen"]] {
        assert_success(&sync(args), &args.join(" "));
        assert_eq!(fs::read_to_string(&lock_path).unwrap(), locked);
    }
    assert_success(&sync(&["sync", "--update"]), "sync --update");
    let updated = fs::read_to_string(&lock_path).unwrap();
    assert!(updated.contains(&pin("2")), "{updated}");
    assert_success(&sync(&["sync", "--frozen"]), "sync --frozen after --update");
}

/// A repository's files by path.
type Served = Vec<(String, Vec<u8>)>;

/// Build `number` of `t:other:1-SNAPSHOT`, deployed at `stamp`: its jar, its
/// jar and POM files, and the metadata the deploy writes.
fn other_build(stamp: &str, number: u32) -> (Vec<u8>, Served, String) {
    let bytes = jar(&[("note.txt", stamp.as_bytes())]);
    let pom = "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
               <artifactId>other</artifactId><version>1-SNAPSHOT</version></project>";
    let name = format!("t/other/1-SNAPSHOT/other-1-{stamp}-{number}");
    let updated = stamp.replace('.', "");
    let entry = |extension: &str| {
        format!(
            "<snapshotVersion><extension>{extension}</extension><value>1-{stamp}-{number}\
             </value><updated>{updated}</updated></snapshotVersion>"
        )
    };
    let metadata = format!(
        "<metadata><groupId>t</groupId><artifactId>other</artifactId>\
         <version>1-SNAPSHOT</version><versioning><snapshot><timestamp>{stamp}</timestamp>\
         <buildNumber>{number}</buildNumber></snapshot><lastUpdated>{updated}</lastUpdated>\
         <snapshotVersions>{}{}</snapshotVersions></versioning></metadata>",
        entry("jar"),
        entry("pom")
    );
    let files = vec![
        (format!("{name}.jar"), bytes.clone()),
        (format!("{name}.pom"), pom.as_bytes().to_vec()),
    ];
    (bytes, files, metadata)
}

/// [`files`], then the `builds` of `t:other` and the `metadata` that names
/// one of them.
fn with_other(builds: &[&Served], metadata: &str) -> Served {
    let mut served: Served = (files(extension_jar(b"one")).into_iter())
        .map(|(path, bytes)| (path.to_string(), bytes))
        .collect();
    served.extend(builds.iter().flat_map(|build| build.iter().cloned()));
    let path = "t/other/1-SNAPSHOT/maven-metadata.xml".to_string();
    served.push((path, metadata.as_bytes().to_vec()));
    served
}

/// A repository that serves what its handle holds, and a [`stand_in`] for
/// what it does not.
fn served_repository(files: Served) -> (StubServer, Arc<Mutex<Served>>) {
    let served = Arc::new(Mutex::new(files));
    let state = Arc::clone(&served);
    let server = StubServer::start(move |request| {
        let files = state.lock().unwrap().clone();
        serve_sha256(request.path.trim_start_matches('/'), |path| {
            let known = files.into_iter().find(|(name, _)| name == path);
            known.map(|(_, body)| body).or_else(|| stand_in(path))
        })
    });
    (server, served)
}

/// A SNAPSHOT-enabled `<repository>` or `<pluginRepository>` (`kind`).
fn snapshot_repository(kind: &str, id: &str, url: &str, policy: &str) -> String {
    format!(
        "<{kind}><id>{id}</id><url>{url}</url><releases><enabled>false</enabled></releases>\
         <snapshots><enabled>true</enabled><updatePolicy>{policy}</updatePolicy></snapshots>\
         </{kind}>"
    )
}

/// A project whose `t:app` takes the `executable-war` type of the `t:ext:2`
/// extension, so its resolution reads the `t:other:1-SNAPSHOT` extension
/// too, with `plugin_repositories` and `more` in its POM.
fn other_extension_project(root: &std::path::Path, plugin_repositories: &str, more: &str) {
    fs::write(
        root.join("pom.xml"),
        pom(
            "demo",
            &format!(
                "<dependencies><dependency><groupId>t</groupId><artifactId>app</artifactId>\
                 <version>1</version><type>executable-war</type></dependency></dependencies>\
                 <build><extensions><extension><groupId>t</groupId><artifactId>other\
                 </artifactId><version>1-SNAPSHOT</version></extension><extension>\
                 <groupId>t</groupId><artifactId>ext</artifactId><version>2</version>\
                 </extension></extensions></build><pluginRepositories>{plugin_repositories}\
                 </pluginRepositories>{more}"
            ),
        ),
    )
    .unwrap();
}

/// A SNAPSHOT build extension a module reads holds the build raeva.lock
/// pins, as a SNAPSHOT dependency does: `--frozen` on a fresh home takes
/// that build after a newer one is deployed, a seed carries it, and
/// `--frozen` fails once it is gone.
#[test]
fn frozen_takes_the_locked_build_of_a_snapshot_extension() {
    let (first, first_files, first_metadata) = other_build("20240101.010101", 1);
    let (_, second_files, second_metadata) = other_build("20240202.020202", 2);
    let (server, served) = served_repository(with_other(&[&first_files], &first_metadata));
    let url = format!("http://{}/", server.addr());
    let project = TempDir::new().unwrap();
    let root = project.path();
    let repository = snapshot_repository("pluginRepository", "snapshots", &url, "daily");
    other_extension_project(root, &repository, "");
    let run = |home: &TempDir, args: &[&str]| run_raeva(root, home.path(), args);
    let synced = home(&url);
    assert_success(&run(&synced, &["sync"]), "sync");
    let lock_path = root.join("raeva.lock");
    let locked = fs::read_to_string(&lock_path).unwrap();
    let pin = format!("t:other:1-20240101.010101-1\\t{}", sha256_hex(&first));
    assert!(locked.contains(&pin), "{locked}");
    let seed = synced.path().join("seed");
    let seed = seed.to_str().unwrap();
    assert_success(&run(&synced, &["seed", "save", seed]), "seed save");

    *served.lock().unwrap() = with_other(&[&first_files, &second_files], &second_metadata);
    let fresh = home(&url);
    assert_success(
        &run(&fresh, &["sync", "--frozen"]),
        "--frozen after a redeploy",
    );
    assert_eq!(fs::read_to_string(&lock_path).unwrap(), locked);
    let offline = run(&fresh, &["--offline", "sync", "--frozen"]);
    assert_success(&offline, "offline --frozen after a redeploy");
    let restored = home(&url);
    assert_success(&run(&restored, &["seed", "restore", seed]), "seed restore");
    let before = server.requests().len();
    let offline = run(&restored, &["--offline", "sync", "--frozen"]);
    assert_success(&offline, "offline --frozen after a restore");
    assert_eq!(server.requests().len(), before);

    *served.lock().unwrap() = with_other(&[&second_files], &second_metadata);
    let output = run(&home(&url), &["sync", "--frozen"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(5), "{stderr}");
    assert!(stderr.contains("t:other:1-20240101.010101-1"), "{stderr}");
    assert_eq!(fs::read_to_string(&lock_path).unwrap(), locked);
}

/// A reactor module's SNAPSHOT build extension holds its locked build
/// under `--frozen` too, by the module's `sub/pom.xml` on every OS.
#[test]
fn frozen_takes_the_locked_build_of_a_module_snapshot_extension() {
    let (_, first_files, first_metadata) = other_build("20240101.010101", 1);
    let (_, second_files, second_metadata) = other_build("20240202.020202", 2);
    let (server, served) = served_repository(with_other(&[&first_files], &first_metadata));
    let url = format!("http://{}/", server.addr());
    let project = TempDir::new().unwrap();
    let root = project.path();
    let reactor = "<packaging>pom</packaging><modules><module>sub</module></modules>";
    fs::write(root.join("pom.xml"), pom("root", reactor)).unwrap();
    fs::create_dir(root.join("sub")).unwrap();
    let repository = snapshot_repository("pluginRepository", "snapshots", &url, "daily");
    other_extension_project(&root.join("sub"), &repository, "");
    assert_success(&run_raeva(root, home(&url).path(), &["sync"]), "sync");
    let locked = fs::read_to_string(root.join("raeva.lock")).unwrap();
    *served.lock().unwrap() = with_other(&[&first_files, &second_files], &second_metadata);
    let frozen = run_raeva(root, home(&url).path(), &["sync", "--frozen"]);
    assert_success(&frozen, "--frozen after a redeploy");
    assert_eq!(fs::read_to_string(root.join("raeva.lock")).unwrap(), locked);
}

/// A project whose `t:app` takes the `executable-war` type of the
/// `t:carrier:1` extension, which depends on `t:other:1-SNAPSHOT`, from the
/// plugin repository at `url`, served with `builds` and the `metadata` that
/// names one of them.
fn snapshot_realm(root: &std::path::Path, url: &str, builds: &[&Served], metadata: &str) -> Served {
    let carrier_pom = pom(
        "carrier",
        "<dependencies><dependency><groupId>t</groupId><artifactId>other</artifactId>\
         <version>1-SNAPSHOT</version></dependency></dependencies>",
    );
    let mut served = with_other(builds, metadata);
    served.extend([
        (
            "t/carrier/1/carrier-1.pom".to_string(),
            carrier_pom.into_bytes(),
        ),
        (
            "t/carrier/1/carrier-1.jar".to_string(),
            extension_jar(b"carrier"),
        ),
    ]);
    let repository = snapshot_repository("pluginRepository", "snapshots", url, "daily");
    fs::write(
        root.join("pom.xml"),
        pom(
            "demo",
            &format!(
                "<dependencies><dependency><groupId>t</groupId><artifactId>app</artifactId>\
                 <version>1</version><type>executable-war</type></dependency></dependencies>\
                 <build><extensions><extension><groupId>t</groupId><artifactId>carrier\
                 </artifactId><version>1</version></extension></extensions></build>\
                 <pluginRepositories>{repository}</pluginRepositories>"
            ),
        ),
    )
    .unwrap();
    served
}

/// A SNAPSHOT jar of a build extension's realm is pinned at its build, as
/// the extension's own is: `lock verify` checks it, `export-checksums`
/// lists it, a seed carries it, and `--frozen` or `lock verify --download`
/// on a fresh home keeps that build after a newer one is deployed.
#[test]
fn a_snapshot_jar_of_an_extension_realm_holds_its_locked_build() {
    let (first, first_files, first_metadata) = other_build("20240101.010101", 1);
    let (_, second_files, second_metadata) = other_build("20240202.020202", 2);
    let project = TempDir::new().unwrap();
    let root = project.path();
    let (server, served) = served_repository(Vec::new());
    let url = format!("http://{}/", server.addr());
    *served.lock().unwrap() = snapshot_realm(root, &url, &[&first_files], &first_metadata);
    let run = |home: &TempDir, args: &[&str]| run_raeva(root, home.path(), args);
    let synced = home(&url);
    assert_success(&run(&synced, &["sync"]), "sync");
    let lock_path = root.join("raeva.lock");
    let locked = fs::read_to_string(&lock_path).unwrap();
    let pin = format!("t:other:1-20240101.010101-1\\t{}", sha256_hex(&first));
    assert!(locked.contains(&pin), "{locked}");
    assert_success(&run(&synced, &["lock", "verify"]), "lock verify");
    assert_success(&run(&synced, &["export-checksums"]), "export-checksums");
    let summary = fs::read_to_string(root.join(".mvn/checksums/checksums.sha256")).unwrap();
    let line = format!(
        "{}  t/other/1-SNAPSHOT/other-1-20240101.010101-1.jar\n",
        sha256_hex(&first)
    );
    assert!(summary.contains(&line), "{summary}");
    let seed = synced.path().join("seed");
    let seed = seed.to_str().unwrap();
    assert_success(&run(&synced, &["seed", "save", seed]), "seed save");

    *served.lock().unwrap() =
        snapshot_realm(root, &url, &[&first_files, &second_files], &second_metadata);
    let frozen = run(&home(&url), &["sync", "--frozen"]);
    assert_success(&frozen, "--frozen after a redeploy");
    assert_eq!(fs::read_to_string(&lock_path).unwrap(), locked);
    let verified = home(&url);
    let download = run(&verified, &["lock", "verify", "--download"]);
    assert_success(&download, "lock verify --download after a redeploy");
    assert_success(&run(&verified, &["lock", "verify"]), "lock verify");
    let restored = home(&url);
    assert_success(&run(&restored, &["seed", "restore", seed]), "seed restore");
    let before = server.requests().len();
    let offline = run(&restored, &["--offline", "sync", "--frozen"]);
    assert_success(&offline, "offline --frozen after a restore");
    assert_eq!(server.requests().len(), before);
}

/// With `[plugins] lock`, a SNAPSHOT jar of a build extension's realm,
/// which the dependencies read at its build, is refused by the plugin
/// tables, which pin no SNAPSHOT build (exit 5), and no lock is written.
#[test]
fn plugin_locking_refuses_a_snapshot_jar_of_an_extension_realm() {
    let (_, files, metadata) = other_build("20240101.010101", 1);
    let project = TempDir::new().unwrap();
    let root = project.path();
    fs::write(root.join("raeva.toml"), "[plugins]\nlock = true\n").unwrap();
    let (server, served) = served_repository(Vec::new());
    let url = format!("http://{}/", server.addr());
    *served.lock().unwrap() = snapshot_realm(root, &url, &[&files], &metadata);
    let output = run_raeva(root, home(&url).path(), &["sync"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(5), "{stderr}");
    let reason = "While resolving the build-extension t:carrier:1:\n\n\
                  t:other:1-SNAPSHOT:jar is a SNAPSHOT build, which plugin locking does not pin";
    assert!(stderr.contains(reason), "{stderr}");
    assert!(!root.join("raeva.lock").exists());
}

/// A SNAPSHOT jar of an extension's realm whose metadata names another
/// build for its POM is refused (exit 3), as its `extensions` line pins
/// the jar's build alone.
#[test]
fn a_snapshot_realm_jar_whose_pom_is_another_build_is_refused() {
    let (_, first_files, _) = other_build("20240101.010101", 1);
    let (_, second_files, second_metadata) = other_build("20240202.020202", 2);
    let metadata = second_metadata.replacen(
        "<value>1-20240202.020202-2</value>",
        "<value>1-20240101.010101-1</value>",
        1,
    );
    assert_ne!(metadata, second_metadata);
    let project = TempDir::new().unwrap();
    let root = project.path();
    let (server, served) = served_repository(Vec::new());
    let url = format!("http://{}/", server.addr());
    *served.lock().unwrap() = snapshot_realm(root, &url, &[&first_files, &second_files], &metadata);
    let output = run_raeva(root, home(&url).path(), &["sync"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(3), "{stderr}");
    assert!(stderr.contains("whose POM is of another build"), "{stderr}");
    assert!(!root.join("raeva.lock").exists());
}

/// Where a build extension's realm reads `t:bom:1-SNAPSHOT`, whose build
/// decides the version of `t:shared` the realm holds.
#[derive(Clone, Copy, Debug)]
enum RealmBom {
    /// The extension imports it.
    Import,
    /// It is the extension's parent.
    Parent,
    /// It is the parent of the extension's parent, `t:base:1`.
    Grandparent,
    /// The extension's parent, `t:base:1`, imports it.
    ParentImport,
    /// It is the parent of `t:inner:1`, which the extension depends on.
    DependencyParent,
}

/// The jar of `t:shared` at `version`.
fn shared_jar(version: u32) -> Vec<u8> {
    jar(&[("note.txt", format!("shared {version}").as_bytes())])
}

/// A project whose `t:app` takes the `executable-war` type of the
/// `t:carrier:1` extension, declared as a plugin with extensions when
/// `plugin`, from the plugin repository at `url`, whose realm reads
/// `t:bom:1-SNAPSHOT` where `read` says. Builds 1 to `last` of the BOM are
/// served, build `n` managing `t:shared` at version `n`, and the metadata
/// names the last.
fn bom_realm(root: &std::path::Path, url: &str, read: RealmBom, plugin: bool, last: u32) -> Served {
    let mut served: Served = (files(jar(&[])).into_iter())
        .map(|(path, bytes)| (path.to_string(), bytes))
        .collect();
    let parent = |artifact: &str, version: &str| {
        format!(
            "<parent><groupId>t</groupId><artifactId>{artifact}</artifactId>\
             <version>{version}</version><relativePath/></parent>"
        )
    };
    let import = "<dependencyManagement><dependencies><dependency><groupId>t</groupId>\
                  <artifactId>bom</artifactId><version>1-SNAPSHOT</version><type>pom</type>\
                  <scope>import</scope></dependency></dependencies></dependencyManagement>";
    let depends = |artifact: &str, version: &str| {
        format!(
            "<dependencies><dependency><groupId>t</groupId><artifactId>{artifact}</artifactId>\
             {version}</dependency></dependencies>"
        )
    };
    let shared = depends("shared", "");
    let carrier_body = match read {
        RealmBom::Import => format!("{import}{shared}"),
        RealmBom::Parent => format!("{}{shared}", parent("bom", "1-SNAPSHOT")),
        RealmBom::Grandparent | RealmBom::ParentImport => {
            format!("{}{shared}", parent("base", "1"))
        }
        RealmBom::DependencyParent => depends("inner", "<version>1</version>"),
    };
    let base = match read {
        RealmBom::Grandparent => parent("bom", "1-SNAPSHOT") + "<packaging>pom</packaging>",
        _ => format!("<packaging>pom</packaging>{import}"),
    };
    let inner = format!("{}{shared}", parent("bom", "1-SNAPSHOT"));
    let mut put = |path: &str, bytes: Vec<u8>| served.push((path.to_string(), bytes));
    put(
        "t/carrier/1/carrier-1.pom",
        pom("carrier", &carrier_body).into_bytes(),
    );
    put("t/carrier/1/carrier-1.jar", extension_jar(b"carrier"));
    put("t/base/1/base-1.pom", pom("base", &base).into_bytes());
    put("t/inner/1/inner-1.pom", pom("inner", &inner).into_bytes());
    put("t/inner/1/inner-1.jar", jar(&[("note.txt", b"inner")]));
    for version in 1..=2 {
        let pom = pom("shared", "").replace(
            "<version>1</version>",
            &format!("<version>{version}</version>"),
        );
        put(
            &format!("t/shared/{version}/shared-{version}.pom"),
            pom.into_bytes(),
        );
        put(
            &format!("t/shared/{version}/shared-{version}.jar"),
            shared_jar(version),
        );
    }
    let stamp = |number: u32| format!("2024010{number}.010101");
    for number in 1..=last {
        let bom = format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
             <artifactId>bom</artifactId><version>1-SNAPSHOT</version>\
             <packaging>pom</packaging><dependencyManagement><dependencies><dependency>\
             <groupId>t</groupId><artifactId>shared</artifactId><version>{number}</version>\
             </dependency></dependencies></dependencyManagement></project>"
        );
        let name = format!("t/bom/1-SNAPSHOT/bom-1-{}-{number}.pom", stamp(number));
        put(&name, bom.into_bytes());
    }
    let updated = stamp(last).replace('.', "");
    let metadata = format!(
        "<metadata><groupId>t</groupId><artifactId>bom</artifactId>\
         <version>1-SNAPSHOT</version><versioning><snapshot><timestamp>{}</timestamp>\
         <buildNumber>{last}</buildNumber></snapshot><lastUpdated>{updated}</lastUpdated>\
         <snapshotVersions><snapshotVersion><extension>pom</extension>\
         <value>1-{}-{last}</value><updated>{updated}</updated></snapshotVersion>\
         </snapshotVersions></versioning></metadata>",
        stamp(last),
        stamp(last)
    );
    put("t/bom/1-SNAPSHOT/maven-metadata.xml", metadata.into_bytes());
    let carrier = "<groupId>t</groupId><artifactId>carrier</artifactId><version>1</version>";
    let build = if plugin {
        format!("<plugins><plugin>{carrier}<extensions>true</extensions></plugin></plugins>")
    } else {
        format!("<extensions><extension>{carrier}</extension></extensions>")
    };
    let repository = snapshot_repository("pluginRepository", "snapshots", url, "daily");
    fs::write(
        root.join("pom.xml"),
        pom(
            "demo",
            &format!(
                "<dependencies><dependency><groupId>t</groupId><artifactId>app</artifactId>\
                 <version>1</version><type>executable-war</type></dependency></dependencies>\
                 <build>{build}</build><pluginRepositories>{repository}</pluginRepositories>"
            ),
        ),
    )
    .unwrap();
    served
}

/// The SNAPSHOT `t:bom` a build extension's realm reads where `read` says
/// is pinned at its build, in both Maven modes: a fresh home's plain sync
/// keeps the lock and then checks it offline, and after a newer build is
/// deployed `--frozen` and `lock verify --download` on a fresh home and an
/// offline `--frozen` from a seed hold the realm the lock pins, while a
/// plain sync that is due takes the new build.
fn a_snapshot_pom_of_an_extension_realm_holds_its_locked_build(read: RealmBom, plugin: bool) {
    for maven in ["3.9", "3.10"] {
        let context = format!("{read:?}, plugin {plugin}, Maven {maven}");
        let project = TempDir::new().unwrap();
        let root = project.path();
        fs::write(
            root.join("raeva.toml"),
            format!("[lock]\nmaven = \"{maven}\"\n"),
        )
        .unwrap();
        let (server, served) = served_repository(Vec::new());
        let url = format!("http://{}/", server.addr());
        *served.lock().unwrap() = bom_realm(root, &url, read, plugin, 1);
        let run = |home: &TempDir, args: &[&str]| run_raeva(root, home.path(), args);
        let synced = home(&url);
        assert_success(&run(&synced, &["sync"]), &format!("sync, {context}"));
        let lock_path = root.join("raeva.lock");
        let locked = fs::read_to_string(&lock_path).unwrap();
        let shared =
            |version: u32| format!("t:shared:{version}\\t{}", sha256_hex(&shared_jar(version)));
        assert!(locked.contains(&shared(1)), "{context}: {locked}");
        let pin = "coordinate = \"t:bom:1-SNAPSHOT\"";
        assert!(locked.contains(pin), "{context}: {locked}");
        assert!(
            locked.contains("timestamp = \"20240101.010101\""),
            "{context}: {locked}"
        );
        let seed = synced.path().join("seed");
        let seed = seed.to_str().unwrap();
        assert_success(
            &run(&synced, &["seed", "save", seed]),
            &format!("seed save, {context}"),
        );
        let fresh = home(&url);
        assert_success(&run(&fresh, &["sync"]), &format!("fresh sync, {context}"));
        assert_eq!(fs::read_to_string(&lock_path).unwrap(), locked, "{context}");
        let offline = run(&fresh, &["--offline", "sync", "--frozen"]);
        assert_success(
            &offline,
            &format!("offline --frozen after a fresh sync, {context}"),
        );

        *served.lock().unwrap() = bom_realm(root, &url, read, plugin, 2);
        let frozen = run(&home(&url), &["sync", "--frozen"]);
        assert_success(&frozen, &format!("--frozen after a redeploy, {context}"));
        assert_eq!(fs::read_to_string(&lock_path).unwrap(), locked, "{context}");
        let verified = home(&url);
        let download = run(&verified, &["lock", "verify", "--download"]);
        assert_success(&download, &format!("lock verify --download, {context}"));
        let verify = run(&verified, &["lock", "verify"]);
        assert_success(&verify, &format!("lock verify, {context}"));
        let restored = home(&url);
        assert_success(
            &run(&restored, &["seed", "restore", seed]),
            &format!("seed restore, {context}"),
        );
        let before = server.requests().len();
        let offline = run(&restored, &["--offline", "sync", "--frozen"]);
        assert_success(
            &offline,
            &format!("offline --frozen after a restore, {context}"),
        );
        assert_eq!(server.requests().len(), before, "{context}");
        assert_success(
            &run(&home(&url), &["sync"]),
            &format!("sync after a redeploy, {context}"),
        );
        let updated = fs::read_to_string(&lock_path).unwrap();
        assert!(updated.contains(&shared(2)), "{context}: {updated}");
        assert!(
            updated.contains("timestamp = \"20240102.010101\""),
            "{context}: {updated}"
        );
    }
}

#[test]
fn a_snapshot_bom_of_an_extension_realm_holds_its_locked_build() {
    a_snapshot_pom_of_an_extension_realm_holds_its_locked_build(RealmBom::Import, false);
}

#[test]
fn a_snapshot_parent_of_an_extension_realm_holds_its_locked_build() {
    a_snapshot_pom_of_an_extension_realm_holds_its_locked_build(RealmBom::Parent, false);
}

#[test]
fn a_snapshot_grandparent_of_an_extension_realm_holds_its_locked_build() {
    a_snapshot_pom_of_an_extension_realm_holds_its_locked_build(RealmBom::Grandparent, false);
}

#[test]
fn a_snapshot_bom_a_parent_in_an_extension_realm_imports_holds_its_locked_build() {
    a_snapshot_pom_of_an_extension_realm_holds_its_locked_build(RealmBom::ParentImport, false);
}

#[test]
fn a_snapshot_parent_of_a_dependency_in_an_extension_realm_holds_its_locked_build() {
    a_snapshot_pom_of_an_extension_realm_holds_its_locked_build(RealmBom::DependencyParent, false);
}

#[test]
fn a_snapshot_bom_of_a_plugin_extension_realm_holds_its_locked_build() {
    a_snapshot_pom_of_an_extension_realm_holds_its_locked_build(RealmBom::Import, true);
}

/// A plain sync looks for a newer build of a SNAPSHOT build extension once
/// the update policy of the plugin repositories expires, as Maven does
/// online, and takes it into raeva.lock; before that the lock stands. The
/// plugin repository's daily policy counts.
#[test]
fn a_plain_sync_takes_a_newer_snapshot_extension_build_once_its_policy_expires() {
    // `daily` expires at local midnight, so a run across one sees the
    // policy expire and runs again.
    assert!(
        (0..2).any(|_| newer_snapshot_extension_build_once_its_policy_expires()),
        "both runs crossed local midnight"
    );
}

/// The scenario of the test above; false when local midnight passed
/// during it.
fn newer_snapshot_extension_build_once_its_policy_expires() -> bool {
    let start = chrono::Local::now();
    let day = start.date_naive();
    // An age that keeps the check on the day it was made.
    let since_midnight = (day.and_hms_opt(0, 0, 0))
        .and_then(|midnight| midnight.and_local_timezone(chrono::Local).earliest())
        .map_or(0, |midnight| start.timestamp() - midnight.timestamp());
    let (first, first_files, first_metadata) = other_build("20240101.010101", 1);
    let (second, second_files, second_metadata) = other_build("20240202.020202", 2);
    let (server, served) = served_repository(with_other(&[&first_files], &first_metadata));
    let url = format!("http://{}/", server.addr());
    let project = TempDir::new().unwrap();
    let root = project.path();
    let repository = snapshot_repository("pluginRepository", "snapshots", &url, "daily");
    other_extension_project(root, &repository, "");
    let home = home(&url);
    assert_success(&run_raeva(root, home.path(), &["sync"]), "sync");
    let lock_path = root.join("raeva.lock");
    let locked = fs::read_to_string(&lock_path).unwrap();
    assert!(locked.contains(&sha256_hex(&first)), "{locked}");

    *served.lock().unwrap() = with_other(&[&first_files, &second_files], &second_metadata);
    let before = server.requests().len();
    for age in [0, since_midnight.min(3 * 60 * 60)] {
        crate::reactor_sync::age_snapshot_checks(home.path(), &lock_path, age);
        let sync = run_raeva(root, home.path(), &["sync"]);
        assert_success(&sync, &format!("sync {age}s after the check"));
        if chrono::Local::now().date_naive() != day {
            return false;
        }
        assert_eq!(
            fs::read_to_string(&lock_path).unwrap(),
            locked,
            "sync {age}s after the check"
        );
        assert_eq!(server.requests().len(), before);
    }

    let two_days = crate::reactor_sync::TWO_DAYS;
    crate::reactor_sync::age_snapshot_checks(home.path(), &lock_path, two_days);
    assert_success(&run_raeva(root, home.path(), &["sync"]), "sync, policy due");
    let updated = fs::read_to_string(&lock_path).unwrap();
    let pin = format!("t:other:1-20240202.020202-2\\t{}", sha256_hex(&second));
    assert!(updated.contains(&pin), "{updated}");
    true
}

/// Two plugin repositories with other builds of one SNAPSHOT extension:
/// the lock takes the newest across them, as Maven 3.9.12 merges their
/// metadata, and `--frozen` finds that build in the repository that has it.
#[test]
fn a_snapshot_extension_takes_the_newest_build_of_its_plugin_repositories() {
    let (_, first_files, first_metadata) = other_build("20240101.010101", 1);
    let (second, second_files, second_metadata) = other_build("20240202.020202", 2);
    let (older, _) = served_repository(with_other(&[&first_files], &first_metadata));
    let (newer, _) = served_repository(with_other(&[&second_files], &second_metadata));
    let older = format!("http://{}/", older.addr());
    let newer = format!("http://{}/", newer.addr());
    let project = TempDir::new().unwrap();
    let root = project.path();
    let repositories = snapshot_repository("pluginRepository", "older", &older, "daily")
        + &snapshot_repository("pluginRepository", "newer", &newer, "daily");
    other_extension_project(root, &repositories, "");
    let home = || home_mirroring(&older, "central");
    assert_success(&run_raeva(root, home().path(), &["sync"]), "sync");
    let locked = fs::read_to_string(root.join("raeva.lock")).unwrap();
    let pin = format!("t:other:1-20240202.020202-2\\t{}", sha256_hex(&second));
    assert!(locked.contains(&pin), "{locked}");
    let frozen = run_raeva(root, home().path(), &["sync", "--frozen"]);
    assert_success(&frozen, "--frozen on a fresh home");
    assert_eq!(fs::read_to_string(root.join("raeva.lock")).unwrap(), locked);
}

/// A SNAPSHOT extension's jar comes from the plugin repository whose
/// metadata named its build, as Maven 3.9.12 and 3.10.0 resolve it, though
/// a repository listed before it serves a file of that name in other bytes;
/// `--frozen` on a fresh home reads the pinned build from it too.
#[test]
fn a_snapshot_extension_jar_comes_from_the_repository_that_named_its_build() {
    let (_, first_files, first_metadata) = other_build("20240101.010101", 1);
    let (second, second_files, second_metadata) = other_build("20240202.020202", 2);
    let mut older_files = with_other(&[&first_files], &first_metadata);
    older_files.push((
        "t/other/1-SNAPSHOT/other-1-20240202.020202-2.jar".to_string(),
        jar(&[("note.txt", b"other bytes")]),
    ));
    let (older, _) = served_repository(older_files);
    let (newer, newer_served) = served_repository(with_other(&[&second_files], &second_metadata));
    let older = format!("http://{}/", older.addr());
    let newer = format!("http://{}/", newer.addr());
    let project = TempDir::new().unwrap();
    let root = project.path();
    let repositories = snapshot_repository("pluginRepository", "older", &older, "daily")
        + &snapshot_repository("pluginRepository", "newer", &newer, "daily");
    other_extension_project(root, &repositories, "");
    let home = || home_mirroring(&older, "central");
    assert_success(&run_raeva(root, home().path(), &["sync"]), "sync");
    let locked = fs::read_to_string(root.join("raeva.lock")).unwrap();
    let pin = format!("t:other:1-20240202.020202-2\\t{}", sha256_hex(&second));
    assert!(locked.contains(&pin), "{locked}");
    let frozen = run_raeva(root, home().path(), &["sync", "--frozen"]);
    assert_success(&frozen, "--frozen on a fresh home");
    assert_eq!(fs::read_to_string(root.join("raeva.lock")).unwrap(), locked);

    // A newer build deployed after the lock was written: the pinned build
    // still comes from the repository that served it.
    let (_, third_files, third_metadata) = other_build("20240303.030303", 3);
    *newer_served.lock().unwrap() = with_other(&[&second_files, &third_files], &third_metadata);
    let frozen = run_raeva(root, home().path(), &["sync", "--frozen"]);
    assert_success(&frozen, "--frozen after a newer deploy");
    assert_eq!(fs::read_to_string(root.join("raeva.lock")).unwrap(), locked);
}

/// Two modules whose plugin repositories name other builds of one SNAPSHOT
/// extension each lock the build their own repositories name, as Maven
/// 3.9.12 resolves an extension per list of plugin repositories, and
/// `--frozen` holds each module to its build.
#[test]
fn modules_hold_their_own_build_of_one_snapshot_extension() {
    let (first, first_files, first_metadata) = other_build("20240101.010101", 1);
    let (second, second_files, second_metadata) = other_build("20240202.020202", 2);
    let (older, _) = served_repository(with_other(&[&first_files], &first_metadata));
    let (newer, _) = served_repository(with_other(&[&second_files], &second_metadata));
    let older = format!("http://{}/", older.addr());
    let newer = format!("http://{}/", newer.addr());
    let project = TempDir::new().unwrap();
    let root = project.path();
    fs::write(
        root.join("pom.xml"),
        pom(
            "root",
            "<packaging>pom</packaging><modules><module>a</module><module>b</module>\
             <module>c</module></modules>",
        ),
    )
    .unwrap();
    fs::create_dir(root.join("c")).unwrap();
    fs::write(
        root.join("c/pom.xml"),
        pom(
            "c",
            &format!(
                "<dependencies><dependency><groupId>t</groupId><artifactId>other</artifactId>\
                 <version>1-SNAPSHOT</version></dependency></dependencies>\
                 <repositories>{}</repositories>",
                snapshot_repository("repository", "older", &older, "daily")
            ),
        ),
    )
    .unwrap();
    for (module, id, url) in [("a", "older", &older), ("b", "newer", &newer)] {
        let dir = root.join(module);
        fs::create_dir(&dir).unwrap();
        let repository = snapshot_repository("pluginRepository", id, url, "daily");
        other_extension_project(&dir, &repository, "");
        let pom = fs::read_to_string(dir.join("pom.xml")).unwrap().replacen(
            "<artifactId>demo</artifactId>",
            &format!("<artifactId>{module}</artifactId>"),
            1,
        );
        fs::write(dir.join("pom.xml"), pom).unwrap();
    }
    let home = || home_mirroring(&older, "central");
    let synced = home();
    assert_success(&run_raeva(root, synced.path(), &["sync"]), "sync");
    let locked = fs::read_to_string(root.join("raeva.lock")).unwrap();
    for pin in [
        format!("t:other:1-20240101.010101-1\\t{}", sha256_hex(&first)),
        format!("t:other:1-20240202.020202-2\\t{}", sha256_hex(&second)),
    ] {
        assert!(locked.contains(&pin), "{pin}: {locked}");
    }
    for (home, args) in [
        (home(), &["sync", "--frozen"][..]),
        (synced, &["--offline", "sync", "--frozen"]),
    ] {
        assert_success(&run_raeva(root, home.path(), args), &format!("{args:?}"));
        assert_eq!(fs::read_to_string(root.join("raeva.lock")).unwrap(), locked);
    }
}

/// One SNAPSHOT both a dependency and a build extension: both take the same
/// build, `--frozen` holds both after a redeploy, and a sync whose update
/// policy is due moves both to the newer build.
#[test]
fn a_snapshot_dependency_that_is_also_an_extension_holds_one_build() {
    let (first, first_files, first_metadata) = other_build("20240101.010101", 1);
    let (second, second_files, second_metadata) = other_build("20240202.020202", 2);
    let (server, served) = served_repository(with_other(&[&first_files], &first_metadata));
    let url = format!("http://{}/", server.addr());
    let project = TempDir::new().unwrap();
    let root = project.path();
    let plugins = snapshot_repository("pluginRepository", "snapshots", &url, "always");
    let dependencies = format!(
        "<repositories>{}</repositories>",
        snapshot_repository("repository", "snapshots", &url, "always")
    );
    other_extension_project(root, &plugins, &dependencies);
    let pom_path = root.join("pom.xml");
    let pom = fs::read_to_string(&pom_path).unwrap().replacen(
        "</dependencies>",
        "<dependency><groupId>t</groupId><artifactId>other</artifactId>\
         <version>1-SNAPSHOT</version></dependency></dependencies>",
        1,
    );
    fs::write(&pom_path, pom).unwrap();
    let run = |home: &TempDir, args: &[&str]| run_raeva(root, home.path(), args);
    let synced = home(&url);
    assert_success(&run(&synced, &["sync"]), "sync");
    let lock_path = root.join("raeva.lock");
    let locked = fs::read_to_string(&lock_path).unwrap();
    for line in [
        format!("t:other:1-20240101.010101-1\\t{}", sha256_hex(&first)),
        "timestamp = \"20240101.010101\"".to_string(),
    ] {
        assert!(locked.contains(&line), "{line}: {locked}");
    }

    *served.lock().unwrap() = with_other(&[&first_files, &second_files], &second_metadata);
    let frozen = run(&home(&url), &["sync", "--frozen"]);
    assert_success(&frozen, "--frozen after a redeploy");
    assert_eq!(fs::read_to_string(&lock_path).unwrap(), locked);

    assert_success(&run(&synced, &["sync"]), "sync, policy due");
    let updated = fs::read_to_string(&lock_path).unwrap();
    for line in [
        format!("t:other:1-20240202.020202-2\\t{}", sha256_hex(&second)),
        "timestamp = \"20240202.020202\"".to_string(),
    ] {
        assert!(updated.contains(&line), "{line}: {updated}");
    }
    assert!(!updated.contains("20240101.010101"), "{updated}");
}

/// A non-unique SNAPSHOT both a dependency and a build extension, replaced
/// in place, takes one build for both once metadata.db no longer holds its
/// POM: the extension's jar is not the stored one while the dependency's
/// is fetched again with its POM. `--frozen` keeps the stored jar the lock
/// pins.
#[test]
fn a_non_unique_snapshot_extension_takes_the_build_its_pom_is() {
    let build = |note: &str| -> (Vec<u8>, Served) {
        let bytes = jar(&[("note.txt", note.as_bytes())]);
        let pom = format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
             <artifactId>other</artifactId><version>1-SNAPSHOT</version>\
             <name>{note}</name></project>"
        );
        let name = "t/other/1-SNAPSHOT/other-1-SNAPSHOT";
        let files = vec![
            (format!("{name}.jar"), bytes.clone()),
            (format!("{name}.pom"), pom.into_bytes()),
        ];
        (bytes, files)
    };
    let metadata = "<metadata><groupId>t</groupId><artifactId>other</artifactId>\
                    <version>1-SNAPSHOT</version><versioning><lastUpdated>20240101010101\
                    </lastUpdated></versioning></metadata>";
    let (first, first_files) = build("first");
    let (second, second_files) = build("second");
    let (server, served) = served_repository(with_other(&[&first_files], metadata));
    let url = format!("http://{}/", server.addr());
    let project = TempDir::new().unwrap();
    let root = project.path();
    let plugins = snapshot_repository("pluginRepository", "snapshots", &url, "always");
    let dependencies = format!(
        "<repositories>{}</repositories>",
        snapshot_repository("repository", "snapshots", &url, "always")
    );
    other_extension_project(root, &plugins, &dependencies);
    let pom_path = root.join("pom.xml");
    let pom = fs::read_to_string(&pom_path).unwrap().replacen(
        "</dependencies>",
        "<dependency><groupId>t</groupId><artifactId>other</artifactId>\
         <version>1-SNAPSHOT</version></dependency></dependencies>",
        1,
    );
    fs::write(&pom_path, pom).unwrap();
    let synced = home(&url);
    assert_success(&run_raeva(root, synced.path(), &["sync"]), "sync");
    let lock_path = root.join("raeva.lock");
    let locked = fs::read_to_string(&lock_path).unwrap();
    assert!(locked.contains(&sha256_hex(&first)), "{locked}");

    *served.lock().unwrap() = with_other(&[&second_files], metadata);
    let forget_metadata = |home: &std::path::Path| {
        for entry in fs::read_dir(home).unwrap() {
            let path = entry.unwrap().path();
            if (path.file_name().unwrap().to_string_lossy()).starts_with("metadata.db") {
                fs::remove_file(path).unwrap();
            }
        }
    };
    forget_metadata(synced.path());
    assert_success(&run_raeva(root, synced.path(), &["sync"]), "sync");
    let updated = fs::read_to_string(&lock_path).unwrap();
    assert!(
        updated.contains(&format!("t:other:1-SNAPSHOT\\t{}", sha256_hex(&second))),
        "{updated}"
    );
    assert!(!updated.contains(&sha256_hex(&first)), "{updated}");
    let frozen = run_raeva(root, home(&url).path(), &["sync", "--frozen"]);
    assert_success(&frozen, "--frozen on a fresh home");
    // `--frozen` keeps the stored jar of an extension alone, whose POM the
    // lock does not pin, though it fetches that POM again, with the
    // repository's jar gone.
    other_extension_project(root, &plugins, &dependencies);
    assert_success(&run_raeva(root, synced.path(), &["sync"]), "sync");
    served
        .lock()
        .unwrap()
        .retain(|(path, _)| !path.ends_with("SNAPSHOT.jar"));
    forget_metadata(synced.path());
    let frozen = run_raeva(root, synced.path(), &["sync", "--frozen"]);
    assert_success(&frozen, "--frozen with the stored jars");
}

/// A graph that fails leaves no POM in the store that finding the version
/// of a version-less build extension read: a graph pass writes the POMs it
/// read only once every graph is in.
#[test]
fn a_failed_graph_stores_no_pom_an_extension_version_read() {
    let mut files = files(extension_jar(b"one"));
    for (path, bytes) in &mut files {
        if *path == "t/ext/2/ext-2.pom" {
            *bytes = String::from_utf8(bytes.clone())
                .unwrap()
                .replace(
                    "<artifactId>ext</artifactId>",
                    "<parent><groupId>t</groupId><artifactId>base</artifactId>\
                     <version>1</version></parent><artifactId>ext</artifactId>",
                )
                .into_bytes();
        }
    }
    let gone = "<parent><groupId>t</groupId><artifactId>gone</artifactId>\
                <version>1</version></parent>";
    files.push((
        "t/base/1/base-1.pom",
        pom("base", "<packaging>pom</packaging>").into_bytes(),
    ));
    files.push(("t/broken/1/broken-1.pom", pom("broken", gone).into_bytes()));
    let server = StubServer::start(move |request| {
        with_sha256(request.path.trim_start_matches('/'), files.clone())
    });
    let url = format!("http://{}/", server.addr());
    let project = TempDir::new().unwrap();
    let home = home(&url);
    fs::write(
        project.path().join("pom.xml"),
        pom(
            "demo",
            "<dependencies><dependency><groupId>t</groupId><artifactId>app</artifactId>\
             <version>1</version><type>executable-war</type></dependency><dependency>\
             <groupId>t</groupId><artifactId>broken</artifactId><version>1</version>\
             </dependency></dependencies><build><extensions><extension><groupId>t\
             </groupId><artifactId>ext</artifactId></extension></extensions></build>",
        ),
    )
    .unwrap();
    let sync = run_raeva(project.path(), home.path(), &["sync"]);
    assert!(
        !sync.status.success(),
        "{}",
        String::from_utf8_lossy(&sync.stderr)
    );
    let store = rv_store::Store::open(&home.path().join("store")).unwrap();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    for artifact in ["ext", "base"] {
        let version = if artifact == "ext" { "2" } else { "1" };
        let key = rv_maven_types::ArtifactCoord::new("t", artifact, version, "pom", None);
        let stored = runtime.block_on(store.lookup_artifact(&key)).unwrap();
        assert!(stored.is_none(), "{artifact}");
    }
}

/// A type the module itself does not use, met in a dependency's POM, is
/// read then, and the module's management of the war it names applies. A
/// plugin repository that takes no releases is not asked for the extension.
/// `raeva tree` marks an optional direct dependency whose type a build
/// extension defines, or the Maven line: `executable-war` is the war, and
/// on 3.10 `fatjar` the jar, as `mvn dependency:tree` marks them.
#[test]
fn tree_marks_optional_dependencies_of_extension_and_line_types() {
    let server = repository(Arc::new(Mutex::new(extension_jar(b"one"))));
    let url = format!("http://{}/", server.addr());
    let project = TempDir::new().unwrap();
    let root = project.path();
    let home = home(&url);
    fs::write(root.join("raeva.toml"), "[lock]\nmaven = \"3.10\"\n").unwrap();
    fs::write(
        root.join("pom.xml"),
        pom(
            "demo",
            "<dependencies><dependency><groupId>t</groupId><artifactId>app</artifactId>\
             <version>1</version><type>executable-war</type><optional>true</optional>\
             </dependency><dependency><groupId>t</groupId><artifactId>lib</artifactId>\
             <version>1</version><type>fatjar</type><optional>true</optional>\
             </dependency></dependencies><build><extensions><extension><groupId>t\
             </groupId><artifactId>ext</artifactId><version>2</version></extension>\
             </extensions></build>",
        ),
    )
    .unwrap();
    assert_success(&run_raeva(root, home.path(), &["sync"]), "sync");
    // The lock's Maven line decides, though raeva.toml now names another.
    for toml in ["[lock]\nmaven = \"3.10\"\n", "[lock]\nmaven = \"3.9\"\n"] {
        fs::write(root.join("raeva.toml"), toml).unwrap();
        let output = run_raeva(root, home.path(), &["tree"]);
        assert_success(&output, "tree");
        let tree = String::from_utf8_lossy(&output.stdout);
        for line in [
            "t:app:1:war (compile, optional)",
            "t:lib:1 (compile, optional)",
        ] {
            assert!(tree.contains(line), "{toml}{line}\n{tree}");
        }
    }
}

#[test]
fn a_dependency_meets_a_type_of_the_module_extensions() {
    let server = repository(Arc::new(Mutex::new(extension_jar(b"one"))));
    let url = format!("http://{}/", server.addr());
    let project = TempDir::new().unwrap();
    let root = project.path();
    let home = home_mirroring(&url, "central");
    fs::write(
        root.join("pom.xml"),
        pom(
            "demo",
            &format!(
                "<pluginRepositories><pluginRepository><id>snapshots</id><url>{url}</url>\
                 <releases><enabled>false</enabled></releases></pluginRepository>\
                 </pluginRepositories><dependencyManagement><dependencies><dependency><groupId>t</groupId>\
             <artifactId>app</artifactId><version>1</version><type>war</type>\
             </dependency></dependencies></dependencyManagement><dependencies>\
             <dependency><groupId>t</groupId><artifactId>mid</artifactId>\
             <version>1</version></dependency></dependencies><build><plugins><plugin>\
             <groupId>t</groupId><artifactId>ext</artifactId><version>2</version>\
             <extensions>true</extensions></plugin></plugins></build>"
            ),
        ),
    )
    .unwrap();
    let output = raeva_command(root, home.path())
        .arg("sync")
        .output()
        .unwrap();
    assert_success(&output, "sync");
    let locked = fs::read_to_string(root.join("raeva.lock")).unwrap();
    for line in [
        "t:app:1\\twar",
        "t:lib:1\\tjar",
        "extensions = \"t:ext:2\\t",
    ] {
        assert!(locked.contains(line), "{line}: {locked}");
    }
}

/// Reading the extensions' handlers records no input for a profile that
/// changes only the build plugins, as the dependency graph does not read
/// one, so `--frozen` on a JDK or with a property that profile reads
/// accepts the lock.
#[test]
fn a_profile_of_plugins_alone_is_no_input_of_the_extension_types() {
    let server = repository(Arc::new(Mutex::new(extension_jar(b"one"))));
    let url = format!("http://{}/", server.addr());
    let project = TempDir::new().unwrap();
    let root = project.path();
    let home = home(&url);
    let plugin = "<build><plugins><plugin><groupId>t</groupId><artifactId>other</artifactId>\
                  <version>1</version></plugin></plugins></build>";
    fs::write(
        root.join("pom.xml"),
        pom(
            "demo",
            &format!(
                "<dependencies><dependency><groupId>t</groupId><artifactId>app</artifactId>\
                 <version>1</version><type>executable-war</type></dependency></dependencies>\
                 <build><extensions><extension><groupId>t</groupId><artifactId>ext\
                 </artifactId><version>2</version></extension></extensions></build>\
                 <profiles><profile><id>quality</id><activation><property><name>quality\
                 </name></property></activation>{plugin}</profile><profile><id>modern</id>\
                 <activation><jdk>[17,)</jdk></activation>{plugin}</profile></profiles>"
            ),
        ),
    )
    .unwrap();
    let sync = |java: &str, args: &[&str]| {
        raeva_command(root, home.path())
            .env("JAVA_VERSION", java)
            .args(args)
            .output()
            .unwrap()
    };
    assert_success(&sync("21", &["sync"]), "sync");
    let locked = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(locked.contains("extensions = \"t:ext:2\\t"), "{locked}");
    for input in ["user-property:quality", "jdk:[17,)"] {
        assert!(!locked.contains(input), "{input}: {locked}");
    }
    assert_success(&sync("11", &["sync", "--frozen"]), "sync --frozen on 11");
    assert_eq!(fs::read_to_string(root.join("raeva.lock")).unwrap(), locked);
}

/// After an input of the build extensions changed, `--frozen` and
/// `export-m2` refuse raeva.lock as out of date without resolving, and a
/// plain sync resolves again to the graph Maven builds now, where `t:app`
/// has the type `now`.
fn assert_relocked(
    sync: impl Fn(&[&str]) -> std::process::Output,
    root: &std::path::Path,
    now: &str,
) {
    let output = sync(&["sync", "--frozen"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(7), "{stderr}");
    assert!(stderr.contains("the configuration changed"), "{stderr}");
    let m2 = TempDir::new().unwrap();
    let output = sync(&["export-m2", "--m2-path", m2.path().to_str().unwrap()]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(7), "{stderr}");
    assert_success(&sync(&["sync"]), "sync");
    let locked = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(locked.contains(&format!("t:app:1\\t{now}")), "{locked}");
}

/// Maven loads the build extension at the version `.mvn/jvm.config` gives,
/// a system property, and as an extension only when the `<extensions>`
/// value it gives is `true`, so those values are inputs of the graph.
#[test]
fn an_extension_version_from_jvm_config_is_a_graph_input() {
    let server = repository(Arc::new(Mutex::new(extension_jar(b"one"))));
    let url = format!("http://{}/", server.addr());
    let home = home(&url);
    let cases = [
        (
            "<extensions><extension><groupId>t</groupId><artifactId>ext</artifactId>\
             <version>${ext.version}</version></extension></extensions>",
            ["-Dext.version=2\n", "-Dext.version=1\n"],
            ["war", "executable-war"],
        ),
        (
            "<plugins><plugin><groupId>t</groupId><artifactId>ext</artifactId>\
             <version>2</version><extensions>${ext.on}</extensions></plugin></plugins>",
            ["-Dext.on=false\n", "-Dext.on=true\n"],
            ["executable-war", "war"],
        ),
    ];
    for (build, [before, after], [then, now]) in cases {
        let project = TempDir::new().unwrap();
        let root = project.path();
        fs::write(
            root.join("pom.xml"),
            pom(
                "demo",
                &format!(
                    "<dependencies><dependency><groupId>t</groupId><artifactId>app\
                     </artifactId><version>1</version><type>executable-war</type>\
                     </dependency></dependencies><build>{build}</build>"
                ),
            ),
        )
        .unwrap();
        fs::create_dir_all(root.join(".mvn")).unwrap();
        let jvm_config = root.join(".mvn/jvm.config");
        fs::write(&jvm_config, before).unwrap();
        let sync = |args: &[&str]| {
            raeva_command(root, home.path())
                .args(args)
                .output()
                .unwrap()
        };
        assert_success(&sync(&["sync"]), before);
        let locked = fs::read_to_string(root.join("raeva.lock")).unwrap();
        assert!(locked.contains(&format!("t:app:1\\t{then}")), "{locked}");
        assert_success(&sync(&["sync", "--frozen"]), before);
        fs::write(&jvm_config, after).unwrap();
        assert_relocked(sync, root, now);
    }
}

/// A profile that adds a plugin as a build extension changes the graph
/// through the types the extension defines, so its condition is an input:
/// a JDK or a `.mvn/jvm.config` property on which it is off. So is one that
/// adds a plugin plugin management marks as an extension.
#[test]
fn a_profile_that_adds_a_build_extension_is_a_graph_input() {
    let server = repository(Arc::new(Mutex::new(extension_jar(b"one"))));
    let url = format!("http://{}/", server.addr());
    let home = home(&url);
    let marked = "<version>2</version><extensions>true</extensions>";
    let managed = format!(
        "<build><pluginManagement><plugins><plugin><groupId>t</groupId>\
         <artifactId>ext</artifactId>{marked}</plugin></plugins></pluginManagement></build>"
    );
    for (activation, (build, plugin)) in [
        ("<jdk>[21,)</jdk>", ("", marked)),
        ("<property><name>with.ext</name></property>", ("", marked)),
        ("<jdk>[21,)</jdk>", (managed.as_str(), "")),
    ] {
        let project = TempDir::new().unwrap();
        let root = project.path();
        fs::write(
            root.join("pom.xml"),
            pom(
                "demo",
                &format!(
                    "<dependencies><dependency><groupId>t</groupId><artifactId>app\
                     </artifactId><version>1</version><type>executable-war</type>\
                     </dependency></dependencies>{build}<profiles><profile><id>ext</id>\
                     <activation>{activation}</activation><build><plugins><plugin>\
                     <groupId>t</groupId><artifactId>ext</artifactId>{plugin}</plugin>\
                     </plugins></build></profile></profiles>"
                ),
            ),
        )
        .unwrap();
        fs::create_dir_all(root.join(".mvn")).unwrap();
        let jvm_config = root.join(".mvn/jvm.config");
        fs::write(&jvm_config, "-Dwith.ext=true\n").unwrap();
        let sync = |java: &str, args: &[&str]| {
            raeva_command(root, home.path())
                .env("JAVA_VERSION", java)
                .args(args)
                .output()
                .unwrap()
        };
        assert_success(&sync("21", &["sync"]), activation);
        let locked = fs::read_to_string(root.join("raeva.lock")).unwrap();
        assert!(locked.contains("t:app:1\\twar"), "{activation}: {locked}");
        assert_success(&sync("21", &["sync", "--frozen"]), activation);
        if activation.starts_with("<jdk>") {
            assert_relocked(|args: &[&str]| sync("17", args), root, "executable-war");
        } else {
            fs::write(&jvm_config, "").unwrap();
            assert_relocked(|args: &[&str]| sync("21", args), root, "executable-war");
        }
    }
}

/// A release jar that is both a dependency from one repository and a
/// build extension from a plugin repository: a seed carries the plugin
/// repository's route too, which an offline `--frozen` reads it through.
#[test]
fn a_seed_carries_the_plugin_repository_route_of_an_extension_also_a_dependency() {
    let other = jar(&[("note.txt", b"other")]);
    let other_pom = "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
                     <artifactId>other</artifactId><version>1</version></project>";
    let mut central = files(extension_jar(b"one"));
    central.push(("t/other/1/other-1.jar", other.clone()));
    central.push(("t/other/1/other-1.pom", other_pom.as_bytes().to_vec()));
    let plugins = central.clone();
    let central = StubServer::start(move |request| {
        with_sha256(request.path.trim_start_matches('/'), central.clone())
    });
    let plugins = StubServer::start(move |request| {
        with_sha256(request.path.trim_start_matches('/'), plugins.clone())
    });
    let (url, plugins_url) = (
        format!("http://{}/", central.addr()),
        format!("http://{}/", plugins.addr()),
    );
    let project = TempDir::new().unwrap();
    let root = project.path();
    fs::write(
        root.join("pom.xml"),
        pom(
            "demo",
            &format!(
                "<dependencies><dependency><groupId>t</groupId><artifactId>app</artifactId>\
                 <version>1</version><type>executable-war</type></dependency><dependency>\
                 <groupId>t</groupId><artifactId>other</artifactId><version>1</version>\
                 </dependency></dependencies><build><extensions><extension><groupId>t\
                 </groupId><artifactId>other</artifactId><version>1</version></extension>\
                 <extension><groupId>t</groupId><artifactId>ext</artifactId><version>2\
                 </version></extension></extensions></build><pluginRepositories>\
                 <pluginRepository><id>plugins</id><url>{plugins_url}</url>\
                 </pluginRepository></pluginRepositories>"
            ),
        ),
    )
    .unwrap();
    let home = || home_mirroring(&url, "central");
    let run = |home: &TempDir, args: &[&str]| run_raeva(root, home.path(), args);
    let synced = home();
    assert_success(&run(&synced, &["sync"]), "sync");
    let seed = synced.path().join("seed");
    let seed = seed.to_str().unwrap();
    assert_success(&run(&synced, &["seed", "save", seed]), "seed save");
    let restored = home();
    assert_success(&run(&restored, &["seed", "restore", seed]), "seed restore");
    let before = (central.requests().len(), plugins.requests().len());
    let offline = run(&restored, &["--offline", "sync", "--frozen"]);
    assert_success(&offline, "offline sync --frozen after a restore");
    assert_eq!((central.requests().len(), plugins.requests().len()), before);
}

/// A version-less build extension whose handlers type a dependency stays
/// at the version raeva.lock took in a frozen check after the plugin
/// repository marks a newer one and still lists it.
#[test]
fn frozen_holds_a_version_less_extension_that_types_a_dependency() {
    let plugin = "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
                  <artifactId>ext</artifactId><version>3</version>\
                  <packaging>maven-plugin</packaging></project>";
    let listed = |release: &str, versions: &str| -> Served {
        let mut served: Served = (files(extension_jar(b"one")).into_iter())
            .filter(|(path, _)| *path != "t/ext/maven-metadata.xml")
            .map(|(path, bytes)| (path.to_string(), bytes))
            .collect();
        served.push(("t/ext/3/ext-3.pom".into(), plugin.as_bytes().to_vec()));
        served.push(("t/ext/3/ext-3.jar".into(), extension_jar(b"three")));
        let build = "t/ext/4-SNAPSHOT/ext-4-20240101.010101-1";
        served.push((
            format!("{build}.pom"),
            plugin.replace(">3<", ">4-SNAPSHOT<").into(),
        ));
        served.push((format!("{build}.jar"), extension_jar(b"four")));
        let metadata = format!(
            "<metadata><groupId>t</groupId><artifactId>ext</artifactId><versioning>\
             <release>{release}</release><versions>{versions}</versions></versioning>\
             </metadata>"
        );
        served.push(("t/ext/maven-metadata.xml".into(), metadata.into_bytes()));
        served
    };
    let (server, state) = served_repository(Vec::new());
    let url = format!("http://{}/", server.addr());
    let project = TempDir::new().unwrap();
    let root = project.path();
    // Also beside a plugin of the same name that names `3` itself, or a
    // SNAPSHOT build listed before.
    let named = |version: &str| {
        format!(
            "<plugins><plugin><groupId>t</groupId><artifactId>ext</artifactId>\
             <version>{version}</version><extensions>true</extensions></plugin></plugins>"
        )
    };
    let repository = format!(
        "<pluginRepositories><pluginRepository><id>both</id><url>{url}</url><snapshots>\
         <enabled>true</enabled></snapshots></pluginRepository></pluginRepositories>"
    );
    for (plugins, snapshot) in [
        (String::new(), ""),
        (named("3"), ""),
        (
            named("4-20240101.010101-1"),
            "<version>4-SNAPSHOT</version>",
        ),
    ] {
        let versions = format!("<version>1</version><version>2</version>{snapshot}");
        *state.lock().unwrap() = listed("2", &versions);
        let _ = fs::remove_file(root.join("raeva.lock"));
        fs::write(
            root.join("pom.xml"),
            pom(
                "demo",
                &format!(
                    "<dependencies><dependency><groupId>t</groupId><artifactId>app\
                     </artifactId><version>1</version><type>executable-war</type>\
                     </dependency></dependencies><build><extensions><extension><groupId>t\
                     </groupId><artifactId>ext</artifactId></extension></extensions>\
                     {plugins}</build>{repository}"
                ),
            ),
        )
        .unwrap();
        let sync = |home: &TempDir, args: &[&str]| run_raeva(root, home.path(), args);
        assert_success(&sync(&home(&url), &["sync"]), "sync");
        let locked = fs::read_to_string(root.join("raeva.lock")).unwrap();
        assert!(locked.contains("t:ext:2\\t"), "{locked}");
        *state.lock().unwrap() = listed("3", &format!("{versions}<version>3</version>"));
        assert_success(
            &sync(&home(&url), &["sync", "--frozen"]),
            &format!("frozen after the release moved {plugins}"),
        );
        assert_eq!(fs::read_to_string(root.join("raeva.lock")).unwrap(), locked);
    }
}

/// The same for a version-less SNAPSHOT extension, which raeva.lock pins
/// at its build: a frozen check holds it after a release is marked.
#[test]
fn frozen_holds_a_version_less_snapshot_extension_that_types_a_dependency() {
    let (_, build, metadata) = other_build("20240101.010101", 1);
    let listing = |release: &str, versions: &str| {
        let path = "t/other/maven-metadata.xml".to_string();
        let text = format!(
            "<metadata><groupId>t</groupId><artifactId>other</artifactId><versioning>\
             {release}<latest>1-SNAPSHOT</latest><versions>{versions}</versions>\
             </versioning></metadata>"
        );
        (path, text.into_bytes())
    };
    let mut served = with_other(&[&build], &metadata);
    served.push(listing("", "<version>1-SNAPSHOT</version>"));
    let (server, state) = served_repository(served.clone());
    let url = format!("http://{}/", server.addr());
    let project = TempDir::new().unwrap();
    let root = project.path();
    let repository = format!(
        "<pluginRepository><id>both</id><url>{url}</url><snapshots><enabled>true\
         </enabled></snapshots></pluginRepository>"
    );
    fs::write(
        root.join("pom.xml"),
        pom(
            "demo",
            &format!(
                "<dependencies><dependency><groupId>t</groupId><artifactId>app</artifactId>\
                 <version>1</version><type>executable-war</type></dependency></dependencies>\
                 <build><extensions><extension><groupId>t</groupId><artifactId>other\
                 </artifactId></extension><extension><groupId>t</groupId><artifactId>ext\
                 </artifactId><version>2</version></extension></extensions></build>\
                 <pluginRepositories>{repository}</pluginRepositories>"
            ),
        ),
    )
    .unwrap();
    let sync = |home: &TempDir, args: &[&str]| run_raeva(root, home.path(), args);
    assert_success(&sync(&home(&url), &["sync"]), "sync");
    let locked = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(
        locked.contains("t:other:1-20240101.010101-1\\t"),
        "{locked}"
    );

    let pom = "<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>\
               <artifactId>other</artifactId><version>2</version></project>";
    served.retain(|(path, _)| path != "t/other/maven-metadata.xml");
    served.push(listing(
        "<release>2</release>",
        "<version>1-SNAPSHOT</version><version>2</version>",
    ));
    served.push(("t/other/2/other-2.pom".to_string(), pom.as_bytes().to_vec()));
    served.push((
        "t/other/2/other-2.jar".to_string(),
        jar(&[("note.txt", b"2")]),
    ));
    *state.lock().unwrap() = served;
    assert_success(
        &sync(&home(&url), &["sync", "--frozen"]),
        "frozen after a release was marked",
    );
    assert_eq!(fs::read_to_string(root.join("raeva.lock")).unwrap(), locked);
}

/// A build extension a remote parent taken on its `.sha1` declares is
/// downloaded with the jar's own checksum files, but the store indexes it
/// only once that parent's `.sha256` has been checked: a parent whose
/// `.sha256` holds another digest fails the sync and leaves no row for the
/// extension it named.
#[test]
fn a_parent_that_fails_its_late_sha256_leaves_no_row_for_its_extension() {
    const HELD: std::time::Duration = std::time::Duration::from_millis(1500);
    let mut files = files(extension_jar(b"one"));
    files.push((
        "t/p1/1/p1-1.pom",
        pom(
            "p1",
            "<parent><groupId>t</groupId><artifactId>p2</artifactId><version>1</version>\
             </parent><packaging>pom</packaging>",
        )
        .into_bytes(),
    ));
    files.push((
        "t/p2/1/p2-1.pom",
        pom(
            "p2",
            "<packaging>pom</packaging><build><extensions><extension><groupId>t</groupId>\
             <artifactId>ext</artifactId><version>2</version></extension></extensions>\
             </build>",
        )
        .into_bytes(),
    ));
    let server = StubServer::start(move |request| {
        let path = request.path.trim_start_matches('/');
        let (file, sidecar) = path
            .rsplit_once('.')
            .filter(|(_, sidecar)| matches!(*sidecar, "sha1" | "sha256"))
            .unwrap_or((path, ""));
        let Some((_, body)) = files.iter().find(|(name, _)| *name == file) else {
            return Response::new(404, "");
        };
        // p1's `.sha256` is missing, and known to be before p2 is named.
        match (file, sidecar) {
            ("t/p1/1/p1-1.pom", "") => Response::new(200, body.clone()).delayed(HELD / 4),
            (_, "") => Response::new(200, body.clone()),
            (_, "sha1") => Response::new(200, sha1_hex(body)),
            ("t/p1/1/p1-1.pom", _) => Response::new(404, ""),
            ("t/p2/1/p2-1.pom", _) => Response::new(200, "0".repeat(64)).delayed(HELD),
            _ => Response::new(200, sha256_hex(body)),
        }
    });
    let url = format!("http://{}/", server.addr());
    let project = TempDir::new().unwrap();
    let home = home(&url);
    fs::write(
        project.path().join("pom.xml"),
        "<project><modelVersion>4.0.0</modelVersion><parent><groupId>t</groupId>\
         <artifactId>p1</artifactId><version>1</version><relativePath/></parent>\
         <artifactId>demo</artifactId><dependencies><dependency><groupId>t</groupId>\
         <artifactId>app</artifactId><version>1</version><type>executable-war</type>\
         </dependency></dependencies></project>",
    )
    .unwrap();
    let sync = run_raeva(project.path(), home.path(), &["sync"]);
    let stderr = String::from_utf8_lossy(&sync.stderr);
    assert_eq!(sync.status.code(), Some(9), "{stderr}");
    assert!(
        stderr.contains("checksum mismatch for t/p2/1/p2-1.pom"),
        "{stderr}"
    );
    assert!(
        (server.requests().iter()).any(|request| request.path == "/t/ext/2/ext-2.jar"),
        "the extension was not read before the parent's .sha256 answered"
    );
    let store = rv_store::Store::open(&home.path().join("store")).unwrap();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let key = rv_maven_types::ArtifactCoord::new("t", "ext", "2", "jar", None);
    let stored = runtime.block_on(store.lookup_artifact(&key)).unwrap();
    assert!(stored.is_none(), "{stored:?}");
}

/// The pom of a project whose test dependency `t:app` is an
/// `executable-war`, the type the version-less extension `t:ext` defines.
fn executable_war_project() -> String {
    pom(
        "demo",
        "<dependencies><dependency><groupId>t</groupId><artifactId>app</artifactId>\
         <version>1</version><type>executable-war</type><scope>test</scope>\
         </dependency></dependencies><build><extensions><extension><groupId>t\
         </groupId><artifactId>ext</artifactId></extension></extensions></build>",
    )
}

/// An extension jar raeva cannot read fails the sync, naming the extension
/// and the entry, where Maven 3.9.12 and 3.10.0 go on without its handlers
/// and take the `executable-war` file the repository also serves: raeva
/// cannot tell every entry Java fails to read from one only raeva does.
/// No raeva.lock is written, and `--frozen` refuses a lock that pins such
/// a jar.
#[test]
fn an_extension_jar_that_does_not_read_fails_the_sync() {
    // The local header of `components.xml`, the jar's first entry, is not
    // one, which Java refuses too.
    let mut bad = extension_jar(b"one");
    bad[..4].copy_from_slice(b"PK\x03\x05");
    let ext = Arc::new(Mutex::new(bad.clone()));
    let server = repository(Arc::clone(&ext));
    let url = format!("http://{}/", server.addr());
    let project = TempDir::new().unwrap();
    let root = project.path();
    fs::write(root.join("pom.xml"), executable_war_project()).unwrap();
    let refused = |output: std::process::Output| {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(5), "{stderr}");
        let named = "raeva cannot read the jar of t:ext:2, entry META-INF/plexus/components.xml";
        assert!(stderr.contains(named), "{stderr}");
        assert!(!stderr.contains("POM"), "{stderr}");
    };
    refused(run_raeva(root, home(&url).path(), &["sync"]));
    let lock_path = root.join("raeva.lock");
    assert!(!lock_path.exists());

    *ext.lock().unwrap() = extension_jar(b"one");
    assert_success(&run_raeva(root, home(&url).path(), &["sync"]), "sync");
    let locked = fs::read_to_string(&lock_path).unwrap();
    let pinned = sha256_hex(&extension_jar(b"one"));
    assert!(locked.contains(&pinned), "{locked}");
    fs::write(&lock_path, locked.replace(&pinned, &sha256_hex(&bad))).unwrap();
    *ext.lock().unwrap() = bad;
    refused(run_raeva(root, home(&url).path(), &["sync", "--frozen"]));
}

/// An extension whose deflated `components.xml` records one byte more than
/// it inflates to defines its type, as Java reads it and Maven 3.9.12 and
/// 3.10.0 resolve `t:app` as its war: raeva locks the war, not the
/// `executable-war` file, and `--frozen` holds it.
#[test]
fn an_extension_descriptor_whose_size_lies_defines_its_type() {
    // A deflate stream of one stored block holds the descriptor as it is.
    let mut ext = extension_jar(b"one");
    let size = u16::from_le_bytes([ext[18], ext[19]]);
    let name_len = usize::from(u16::from_le_bytes([ext[26], ext[27]]));
    let data = 30 + name_len;
    let mut block = vec![1];
    block.extend_from_slice(&size.to_le_bytes());
    block.extend_from_slice(&(!size).to_le_bytes());
    ext.splice(data..data, block);
    let directory = ext.len() - 22;
    let start = u32::from_le_bytes(ext[directory + 16..directory + 20].try_into().unwrap()) + 5;
    ext[directory + 16..directory + 20].copy_from_slice(&start.to_le_bytes());
    let start = start as usize;
    let note = start + 46 + name_len;
    let offset = u32::from_le_bytes(ext[note + 42..note + 46].try_into().unwrap()) + 5;
    ext[note + 42..note + 46].copy_from_slice(&offset.to_le_bytes());
    ext[8] = 8;
    ext[start + 10] = 8;
    let compressed = (u32::from(size) + 5).to_le_bytes();
    ext[18..22].copy_from_slice(&compressed);
    ext[start + 20..start + 24].copy_from_slice(&compressed);
    ext[start + 24..start + 28].copy_from_slice(&(u32::from(size) + 1).to_le_bytes());

    let server = repository(Arc::new(Mutex::new(ext)));
    let url = format!("http://{}/", server.addr());
    let project = TempDir::new().unwrap();
    let root = project.path();
    fs::write(root.join("pom.xml"), executable_war_project()).unwrap();
    assert_success(&run_raeva(root, home(&url).path(), &["sync"]), "sync");
    let locked = fs::read_to_string(root.join("raeva.lock")).unwrap();
    assert!(locked.contains("t:app:1\\twar\\ttest"), "{locked}");
    let frozen = run_raeva(root, home(&url).path(), &["sync", "--frozen"]);
    assert_success(&frozen, "sync --frozen");
}
