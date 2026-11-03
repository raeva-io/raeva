use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

use rv_lock::{
    LockArtifact, LockModulePackage, LockPlatform, Lockfile, Platform, Scope, SupportPom,
};
use rv_maven_types::{ArtifactCoord, BlobId, Digest, Gav, SnapshotStamp};
use rv_store::Store;
use rv_test_support::fixtures;
use sha1::{Digest as _, Sha1};
use tempfile::{TempDir, tempdir};

use super::{
    ExportOptions, ExportStats, ExportUnit, Exporter, UnitSource, artifact_relative_path,
    folds_case, folds_case_without_writing, lexical_normalize, planned_destinations,
};
use crate::error::{ExportError, ExportFailure};
use crate::link::LinkStrategy;
use crate::metadata::{SnapshotVersionEntry, parse_remote_repositories, read_existing_metadata};
use crate::plan::{ExportPlan, ProjectPom, Reactor};
use crate::warning::ExportWarning;

const REPO: &str = "https://repo.example/maven2/";

struct Fixture {
    _store_dir: TempDir,
    store: Store,
    m2_dir: TempDir,
    lock: Lockfile,
}

impl Fixture {
    fn new() -> Self {
        let store_dir = tempdir().expect("store dir");
        let store = Store::open(store_dir.path()).expect("store");
        let mut lock = Lockfile::new();
        lock.platforms.push(LockPlatform::single_module(
            Platform::new("linux", "x86_64").unwrap(),
            Gav::new("com.example", "root", "1"),
            "pom",
            Vec::new(),
        ));
        Self {
            _store_dir: store_dir,
            store,
            m2_dir: tempdir().expect("m2 dir"),
            lock,
        }
    }

    fn m2(&self) -> PathBuf {
        self.m2_dir.path().join("repository")
    }

    fn read(&self, relative: &str) -> String {
        fs::read_to_string(self.m2().join(relative))
            .unwrap_or_else(|err| panic!("{relative}: {err}"))
    }

    /// Store `bytes` and point the coordinate index at them for `key`.
    async fn put(&self, key: &ArtifactCoord, bytes: &[u8]) -> BlobId {
        self.put_from(key, bytes, REPO).await
    }

    /// Store and index `bytes` for `key`, as `repo` served them.
    async fn put_from(&self, key: &ArtifactCoord, bytes: &[u8], repo: &str) -> BlobId {
        let blob = self.store.put_bytes(bytes).await.expect("put");
        self.store.add_artifact(key, &blob).await.expect("index");
        let origin = rv_store::Origin {
            repo_url: repo.into(),
            endpoint_url: repo.into(),
            checksum_verified: true,
            served: true,
        };
        let served = vec![(key.clone(), blob.clone(), origin)];
        self.store.record_origins(served).await.expect("origin");
        blob
    }

    async fn row(&mut self, mut row: LockArtifact, payload: &[u8], pom: &[u8]) {
        let blob = self.put_from(&row.coord(), payload, &row.repo_url).await;
        row.checksums = vec![Digest::parse("sha256", blob.as_str()).unwrap()];
        let pom_origin = row
            .pom_origins()
            .next()
            .unwrap_or(&row.repo_url)
            .to_string();
        let pom_key = ArtifactCoord::of(row.pom_gav(), "pom", None);
        row.pom_sha256 = Some(self.put_from(&pom_key, pom, &pom_origin).await);
        self.lock.platforms[0].artifacts.push(row);
    }

    async fn support(&mut self, gav: &str, repo_id: &str, bytes: &[u8]) {
        let repo_url = format!("https://{repo_id}.example/");
        let [group, artifact, version] = gav.splitn(3, ':').collect::<Vec<_>>()[..] else {
            panic!("{gav}");
        };
        let key = ArtifactCoord::new(group, artifact, version, "pom", None);
        let blob = self.put_from(&key, bytes, &repo_url).await;
        self.lock
            .repo_ids
            .insert(repo_url.clone(), [repo_id.into()].into());
        self.lock.platforms[0]
            .support_poms
            .insert(gav.to_string(), SupportPom::new(repo_url, blob));
    }

    fn options(&self) -> ExportOptions {
        ExportOptions {
            dry_run: false,
            overwrite: false,
            link_strategy: LinkStrategy::Copy,
            m2_path: self.m2(),
            shared: false,
        }
    }

    fn exporter(&self, options: ExportOptions) -> Exporter<'_> {
        let config = rv_config::Config::for_testing(
            self.m2_dir.path().to_path_buf(),
            rv_config::ResolvedPaths::from_raeva_home(self.m2_dir.path().join("home")),
        );
        let plan = ExportPlan::from_lock(&config, &self.lock, &HashMap::new()).expect("plan");
        Exporter::new(options, &self.store, plan)
    }

    async fn export(&self) -> Result<ExportStats, ExportFailure> {
        self.exporter(self.options())
            .export(&Reactor::default())
            .await
    }

    /// Export, expect it to fail, and check that nothing was written.
    async fn refused(&self) -> ExportError {
        let failure = self.export().await.expect_err("the export must fail");
        assert!(!self.m2().exists(), "written before the refusal: {failure}");
        failure.error
    }
}

fn jar(group: &str, artifact: &str, version: &str) -> LockArtifact {
    LockArtifact::new(
        ArtifactCoord::new(group, artifact, version, "jar", None),
        REPO,
    )
}

fn pom_text(artifact_id: &str, parent: Option<&str>) -> Vec<u8> {
    let parent = parent.map_or_else(String::new, |parent| {
        format!(
            "<parent><groupId>com.example</groupId><artifactId>{parent}</artifactId>\
             <version>1</version></parent>"
        )
    });
    format!(
        "<project><modelVersion>4.0.0</modelVersion>{parent}<groupId>com.example</groupId>\
         <artifactId>{artifact_id}</artifactId><version>1</version></project>"
    )
    .into_bytes()
}

/// Whether `path` is a metadata file that lists no version or build, as
/// the export writes under an id the lock takes nothing from.
fn lists_nothing(path: &Path) -> bool {
    fs::read_to_string(path).is_ok_and(|text| text.contains("<versioning>\n  </versioning>"))
}

fn support_key(artifact_id: &str) -> ArtifactCoord {
    ArtifactCoord::new("com.example", artifact_id, "1", "pom", None)
}

#[tokio::test]
async fn a_release_exports_with_sidecars_markers_and_metadata() {
    let mut f = Fixture::new();
    f.lock.repo_ids.insert(
        rv_lock::recorded_key(REPO).to_string(),
        ["corp".to_string()].into(),
    );
    f.row(jar("com.example", "demo", "1.0.0"), b"jar", b"<project/>")
        .await;

    let stats = f.export().await.expect("export");
    assert_eq!(
        (
            stats.exported_count,
            stats.copied_count,
            stats.skipped_count
        ),
        (2, 2, 0)
    );
    assert!(stats.warnings.is_empty(), "{:?}", stats.warnings);
    let dir = "com/example/demo/1.0.0";
    let jar_path = format!("{dir}/demo-1.0.0.jar");
    assert_eq!(f.read(&jar_path), "jar");
    assert_eq!(f.read(&format!("{dir}/demo-1.0.0.pom")), "<project/>");
    let sha256 = format!("{jar_path}.sha256");
    let sha1 = format!("{jar_path}.sha1");
    assert_eq!(f.read(&sha256), BlobId::from_bytes(b"jar").as_str());
    assert_eq!(f.read(&sha1), hex::encode(Sha1::digest(b"jar")));
    assert_eq!(
        f.read(&format!("{dir}/_remote.repositories")),
        "#NOTE: This is a Maven Resolver internal implementation file, its format can be \
         changed without prior notice.\n#Thu Jan 01 00:00:00 UTC 1970\n\
         demo-1.0.0.jar>corp=\ndemo-1.0.0.pom>corp=\n"
    );
    assert_eq!(
        f.read("com/example/demo/maven-metadata-corp.xml"),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<metadata>\n  <groupId>com.example</groupId>\n  \
         <artifactId>demo</artifactId>\n  <versioning>\n    <latest>1.0.0</latest>\n    \
         <release>1.0.0</release>\n    <versions>\n      <version>1.0.0</version>\n    \
         </versions>\n    <lastUpdated>00000000000000</lastUpdated>\n  </versioning>\n</metadata>\n"
    );
    assert!(!f.m2().join(dir).join("maven-metadata-corp.xml").exists());
    for id in ["central", "local"] {
        let path = f
            .m2()
            .join(format!("com/example/demo/maven-metadata-{id}.xml"));
        assert!(lists_nothing(&path), "{id}");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(f.m2().join(&jar_path))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o644);
    }

    // An identical destination is skipped, and its sidecars are repaired.
    fs::remove_file(f.m2().join(&sha1)).unwrap();
    fs::write(f.m2().join(&sha256), "stale").unwrap();
    let stats = f.export().await.expect("re-export");
    assert_eq!((stats.exported_count, stats.skipped_count), (0, 2));
    assert_eq!(f.read(&sha256), BlobId::from_bytes(b"jar").as_str());
    assert_eq!(f.read(&sha1), hex::encode(Sha1::digest(b"jar")));

    // Other bytes are replaced only with `overwrite`.
    fs::write(f.m2().join(&jar_path), "tampered").unwrap();
    let failure = f
        .export()
        .await
        .expect_err("other bytes at the destination");
    assert!(
        matches!(failure.error, ExportError::DestinationMismatch { .. }),
        "{failure}"
    );
    let mut options = f.options();
    options.overwrite = true;
    f.exporter(options)
        .export(&Reactor::default())
        .await
        .expect("overwrite");
    assert_eq!(f.read(&jar_path), "jar");
}

/// Maven labels a file with every repository it was resolved from: a jar
/// another platform resolved elsewhere, and a POM a classifier jar from
/// another repository shares.
#[tokio::test]
async fn markers_name_every_repository_a_file_came_from() {
    const OTHER: &str = "https://other.example/maven2/";
    let mut f = Fixture::new();
    for (url, id) in [(REPO, "corp"), (OTHER, "other")] {
        f.lock.repo_ids.insert(
            rv_lock::recorded_key(url).to_string(),
            [id.to_string()].into(),
        );
    }
    f.row(jar("com.example", "demo", "1.0.0"), b"jar", b"<project/>")
        .await;
    let mut sources = LockArtifact::new(
        ArtifactCoord::new("com.example", "demo", "1.0.0", "jar", Some("tests")),
        OTHER,
    );
    sources.repo_url = OTHER.to_string();
    f.row(sources, b"tests", b"<project/>").await;
    f.row(jar("com.example", "lib", "1.0.0"), b"lib", b"<project/>")
        .await;
    let mut elsewhere = f.lock.platforms[0].artifacts[2].clone();
    elsewhere.repo_url = OTHER.to_string();
    f.lock.platforms.push(LockPlatform::single_module(
        Platform::new("macos", "aarch64").unwrap(),
        Gav::new("com.example", "root", "1"),
        "pom",
        vec![elsewhere],
    ));

    f.export().await.expect("export");
    let markers = f.read("com/example/demo/1.0.0/_remote.repositories");
    assert!(markers.contains("demo-1.0.0.jar>corp="), "{markers}");
    assert!(!markers.contains("demo-1.0.0.jar>other="), "{markers}");
    assert!(markers.contains("demo-1.0.0-tests.jar>other="), "{markers}");
    assert!(!markers.contains("tests.jar>corp="), "{markers}");
    for id in ["corp", "other"] {
        assert!(
            markers.contains(&format!("demo-1.0.0.pom>{id}=")),
            "{markers}"
        );
    }
    let markers = f.read("com/example/lib/1.0.0/_remote.repositories");
    for id in ["corp", "other"] {
        assert!(
            markers.contains(&format!("lib-1.0.0.jar>{id}=")),
            "{markers}"
        );
        assert!(
            markers.contains(&format!("lib-1.0.0.pom>{id}=")),
            "{markers}"
        );
    }
}

/// A BOM one module imports through one repository and another depends on
/// through another is labelled with both.
#[tokio::test]
async fn a_support_pom_a_package_also_names_keeps_both_ids() {
    const OTHER: &str = "https://other.example/maven2/";
    let mut f = Fixture::new();
    f.lock.repo_ids.insert(
        rv_lock::recorded_key(OTHER).to_string(),
        ["other".to_string()].into(),
    );
    let bom = pom_text("bom", None);
    f.support("com.example:bom:1", "boms", &bom).await;
    let mut row = LockArtifact::new(
        ArtifactCoord::new("com.example", "bom", "1", "pom", None),
        OTHER,
    );
    row.repo_url = OTHER.to_string();
    f.row(row, &bom, &bom).await;

    f.export().await.expect("export");
    let markers = f.read("com/example/bom/1/_remote.repositories");
    for id in ["boms", "other"] {
        assert!(markers.contains(&format!("bom-1.pom>{id}=")), "{markers}");
    }
}

#[tokio::test]
async fn classified_snapshot_exports_the_independently_pinned_pom_build() {
    for with_main in [false, true] {
        let mut f = Fixture::new();
        let build1 = "1.0-20261012.010101-1";
        let build2 = "1.0-20261012.010101-2";
        f.lock
            .repo_ids
            .insert(REPO.to_string(), ["snaps".to_string()].into());
        let mut main = jar("p", "nat", "1.0-SNAPSHOT");
        main.snapshot = SnapshotStamp::of_version(build1);
        if with_main {
            f.row(main, b"main", b"pom").await;
        }
        let mut classified = jar("p", "nat", "1.0-SNAPSHOT");
        classified.coordinate =
            ArtifactCoord::new("p", "nat", "1.0-SNAPSHOT", "jar", Some("linux"));
        classified.snapshot = SnapshotStamp::of_version(build2);
        classified.pom_snapshot = SnapshotStamp::of_version(build1);
        f.row(classified, b"linux", b"pom").await;
        f.export().await.expect("export");
        let dir = "p/nat/1.0-SNAPSHOT";
        assert_eq!(f.read(&format!("{dir}/nat-{build1}.pom")), "pom");
        assert_eq!(f.read(&format!("{dir}/nat-{build2}-linux.jar")), "linux");
        assert_eq!(f.read(&format!("{dir}/nat-1.0-SNAPSHOT.pom")), "pom");
        assert!(!f.m2().join(format!("{dir}/nat-{build2}.pom")).exists());
        let metadata =
            read_existing_metadata(&f.m2().join(format!("{dir}/maven-metadata-snaps.xml")));
        let pom = metadata
            .snapshot_versions
            .iter()
            .find(|entry| entry.extension == "pom")
            .unwrap();
        assert_eq!(pom.value, build1);
        let linux = metadata
            .snapshot_versions
            .iter()
            .find(|entry| entry.classifier.as_deref() == Some("linux"))
            .unwrap();
        assert_eq!(linux.value, build2);
    }
}

/// A `-SNAPSHOT` parent pinned to a build is laid out as Maven 3.9.12 leaves
/// it: the build under its timestamped name, tracked and listed in the
/// version metadata, and an untracked plain copy that a build naming the
/// repository by another id still reads.
#[tokio::test]
async fn a_parent_pinned_to_a_snapshot_build_exports_as_maven_downloads_it() {
    let mut f = Fixture::new();
    f.support("com.example:parent:1.0-SNAPSHOT", "corp", b"build 7")
        .await;
    for pin in f.lock.platforms[0].support_poms.values_mut() {
        pin.snapshot = SnapshotStamp::new("20240101.010101", 7);
    }
    // Served evidence counts under the file read, the build's.
    let err = f.refused().await;
    assert!(matches!(err, ExportError::MissingPinnedPom { .. }), "{err}");
    let build = ArtifactCoord::new(
        "com.example",
        "parent",
        "1.0-20240101.010101-7",
        "pom",
        None,
    );
    f.put_from(&build, b"build 7", "https://corp.example/")
        .await;
    f.export().await.expect("export");
    let dir = "com/example/parent/1.0-SNAPSHOT";
    for file in [
        "parent-1.0-20240101.010101-7.pom",
        "parent-1.0-SNAPSHOT.pom",
    ] {
        assert_eq!(f.read(&format!("{dir}/{file}")), "build 7");
    }
    assert_eq!(
        parse_remote_repositories(&f.read(&format!("{dir}/_remote.repositories"))),
        BTreeSet::from([(
            "parent-1.0-20240101.010101-7.pom".to_string(),
            "corp".to_string()
        )])
    );
    let metadata = read_existing_metadata(&f.m2().join(dir).join("maven-metadata-corp.xml"));
    let values: Vec<_> = (metadata.snapshot_versions.iter())
        .map(|entry| (entry.extension.as_str(), entry.value.as_str()))
        .collect();
    assert_eq!(values, [("pom", "1.0-20240101.010101-7")]);
}

/// Maven merges every repository's SNAPSHOT metadata, so an entry an earlier
/// run left in one repository's file must not outrank the build the lock
/// takes from another repository.
#[tokio::test]
async fn a_snapshot_entry_from_another_repository_replaces_a_stale_one() {
    const OTHER: &str = "https://other.example/maven2/";
    let mut f = Fixture::new();
    for (url, id) in [(REPO, "a"), (OTHER, "b")] {
        f.lock.repo_ids.insert(
            rv_lock::recorded_key(url).to_string(),
            [id.to_string()].into(),
        );
    }
    let row = |classifier, url: &str, build| {
        let mut row = LockArtifact::new(
            ArtifactCoord::new("com.example", "snap", "1.0-SNAPSHOT", "jar", classifier),
            url,
        );
        row.repo_url = url.to_string();
        row.snapshot = SnapshotStamp::of_version(build);
        row
    };
    f.row(row(None, OTHER, "1.0-20240102.010101-2"), b"jar", b"pom")
        .await;
    f.row(
        row(Some("tests"), REPO, "1.0-20240101.010101-1"),
        b"tests",
        b"pom",
    )
    .await;
    let dir = f.m2().join("com/example/snap/1.0-SNAPSHOT");
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("maven-metadata-a.xml"),
        "<metadata><groupId>com.example</groupId><artifactId>snap</artifactId>\
         <version>1.0-SNAPSHOT</version><versioning><snapshot><timestamp>20240103.010101\
         </timestamp><buildNumber>3</buildNumber></snapshot><lastUpdated>20240103010101\
         </lastUpdated><snapshotVersions><snapshotVersion><extension>jar</extension>\
         <value>1.0-20240103.010101-3</value><updated>20240103010101</updated>\
         </snapshotVersion></snapshotVersions></versioning></metadata>",
    )
    .unwrap();
    fs::write(dir.join("maven-metadata-a.xml.sha1"), "0").unwrap();

    f.export().await.expect("export");
    // The checksum Maven saved with the old file no longer matches it.
    assert!(!dir.join("maven-metadata-a.xml.sha1").exists());
    let entries = read_existing_metadata(&dir.join("maven-metadata-a.xml")).snapshot_versions;
    assert!(
        entries
            .iter()
            .all(|entry| entry.classifier.is_some() || entry.extension != "jar"),
        "{entries:?}"
    );
}

/// Maven layouts under `maven-snapshot-layout/`: directory name and the
/// repository id Maven recorded in `maven-metadata-<id>.xml`. A new
/// directory, or a stray file next to `files.txt`, must fail here until a
/// test names it.
const SNAPSHOT_LAYOUTS: &[(&str, &str)] = &[("mirror", "corp"), ("plain", "snaps")];

#[test]
fn every_maven_snapshot_layout_directory_is_used() {
    let root = fixtures::path("maven-snapshot-layout");
    let dirs: Vec<&str> = SNAPSHOT_LAYOUTS.iter().map(|(dir, _)| *dir).collect();
    fixtures::assert_children(&root, &dirs, &[]);
    for &(dir, repo_id) in SNAPSHOT_LAYOUTS {
        let metadata = format!("maven-metadata-{repo_id}.xml");
        fixtures::assert_children(
            &root.join(dir),
            &[],
            &["_remote.repositories", "files.txt", metadata.as_str()],
        );
    }
}

/// The files, `_remote.repositories` entries and version metadata of a
/// snapshot match what Maven 3.9 leaves after downloading it
/// (`test-fixtures/maven-snapshot-layout/`), under the id of the repository
/// or of the mirror in front of it. The sources jar goes through a second
/// pass, as `raeva export-m2 --with-sources` writes it, and the metadata keeps
/// the entries of the first.
#[tokio::test]
async fn a_snapshot_exports_as_maven_downloads_it() {
    let fixture = fixtures::path("maven-snapshot-layout");
    let timestamped = "1.0-20261017.210153-2";
    let url = "http://127.0.0.1:33707/";
    let snapshot_row = |classifier| {
        let mut row = LockArtifact::new(
            ArtifactCoord::new("com.example", "snaplib", "1.0-SNAPSHOT", "jar", classifier),
            url,
        );
        row.snapshot = SnapshotStamp::of_version(timestamped);
        row
    };
    for &(case, repo_id) in SNAPSHOT_LAYOUTS {
        let mut f = Fixture::new();
        f.lock.repo_ids.insert(
            rv_lock::recorded_key(url).to_string(),
            [repo_id.to_string()].into(),
        );
        f.row(snapshot_row(None), b"jar", b"pom").await;
        let sources = snapshot_row(Some("sources"));
        f.put_from(&sources.coord(), b"sources", url).await;

        let exporter = f.exporter(f.options());
        exporter.export(&Reactor::default()).await.expect("export");
        exporter
            .export_items(std::slice::from_ref(&sources))
            .await
            .expect("sources");
        // The timestamped jar and its plain `-SNAPSHOT` copy, not the POM.
        let again = exporter.export_items(&[sources]).await.expect("again");
        assert_eq!(
            (again.exported_count, again.skipped_classified_count),
            (0, 2),
            "{case}"
        );

        let dir = f.m2().join("com/example/snaplib/1.0-SNAPSHOT");
        let maven = fixture.join(case);
        let written: BTreeSet<String> = fs::read_dir(&dir)
            .expect("export dir")
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| !name.ends_with(".sha1") && !name.ends_with(".sha256"))
            .collect();
        let expected: BTreeSet<String> = fs::read_to_string(maven.join("files.txt"))
            .unwrap()
            .lines()
            .filter(|name| !name.ends_with(".sha1") && *name != "resolver-status.properties")
            .map(str::to_string)
            .chain(["central", "local"].map(|id| format!("maven-metadata-{id}.xml")))
            .collect();
        assert_eq!(written, expected, "{case}");
        for id in ["central", "local"] {
            assert!(lists_nothing(&dir.join(format!("maven-metadata-{id}.xml"))));
        }

        let markers = |path: &Path| parse_remote_repositories(&fs::read_to_string(path).unwrap());
        assert_eq!(
            markers(&dir.join("_remote.repositories")),
            markers(&maven.join("_remote.repositories")),
            "{case}"
        );

        let metadata = format!("maven-metadata-{repo_id}.xml");
        let entries = |path: &Path| {
            let mut entries: Vec<_> = read_existing_metadata(path)
                .snapshot_versions
                .into_iter()
                .map(
                    |SnapshotVersionEntry {
                         classifier,
                         extension,
                         value,
                         ..
                     }| { (classifier, extension, value) },
                )
                .collect();
            entries.sort();
            entries
        };
        assert_eq!(
            entries(&dir.join(&metadata)),
            entries(&maven.join(&metadata)),
            "{case}"
        );
        let text = fs::read_to_string(dir.join(&metadata)).unwrap();
        for tag in [
            "<timestamp>20261017.210153</timestamp>",
            "<buildNumber>2</buildNumber>",
            "<version>1.0-SNAPSHOT</version>",
        ] {
            assert!(text.contains(tag), "{case}: {tag}");
        }
        assert!(!text.contains("localCopy"), "{case}");
    }
}

/// `mvn -o` needs every parent and imported BOM. A recorded support POM is
/// exported from its pinned bytes, whatever the coordinate index says, and
/// labelled with its own repository. Every remote parent needs a pin; a
/// parent from the reactor is Maven's to build, not a support POM.
#[tokio::test]
async fn support_poms_around_the_locked_artifacts_are_exported() {
    let mut f = Fixture::new();
    f.row(
        jar("com.example", "demo", "1.0.0"),
        b"jar",
        &pom_text("demo", Some("parent")),
    )
    .await;
    f.support("com.example:parent:1", "central", &pom_text("parent", None))
        .await;
    f.support("com.example:bom:1", "boms", b"pinned bom").await;
    f.put(&support_key("bom"), b"repointed bom").await;
    f.support("com.example:remote-parent:1", "central", b"remote parent")
        .await;

    let project = tempdir().expect("project");
    let project_pom = |name: &str, parent: &str| {
        let path = project.path().join(name);
        fs::write(&path, pom_text(name, Some(parent))).unwrap();
        path
    };
    let reactor = Reactor {
        poms: vec![
            ProjectPom {
                path: project_pom("app", "reactor-parent"),
                local_parent: false,
            },
            ProjectPom {
                path: project_pom("lib", "local-parent"),
                local_parent: true,
            },
            ProjectPom {
                path: project_pom("tool", "remote-parent"),
                local_parent: false,
            },
        ],
        modules: BTreeSet::from([Gav::new("com.example", "reactor-parent", "1")]),
    };
    let stats = f
        .exporter(f.options())
        .export(&reactor)
        .await
        .expect("export");

    assert!(stats.warnings.is_empty());
    assert_eq!(f.read("com/example/bom/1/bom-1.pom"), "pinned bom");
    let markers = |artifact: &str| {
        parse_remote_repositories(
            &f.read(&format!("com/example/{artifact}/1/_remote.repositories")),
        )
    };
    let entry = |file: &str, id: &str| (file.to_string(), id.to_string());
    assert!(markers("bom").contains(&entry("bom-1.pom", "boms")));
    assert!(markers("parent").contains(&entry("parent-1.pom", "central")));
    assert_eq!(
        f.read("com/example/remote-parent/1/remote-parent-1.pom"),
        "remote parent"
    );
    for absent in ["reactor-parent", "local-parent", "grand"] {
        assert!(
            !f.m2().join("com/example").join(absent).exists(),
            "{absent}"
        );
    }
}

/// A stored POM whose bytes changed is not walked for its `<parent>`: the
/// export reports the damage, not a parent the changed bytes name.
#[tokio::test]
async fn a_damaged_pom_reports_the_damage_not_its_parent() {
    let mut f = Fixture::new();
    f.row(
        jar("com.example", "demo", "1"),
        b"jar",
        &pom_text("demo", Some("parent")),
    )
    .await;
    f.support("com.example:parent:1", "central", &pom_text("parent", None))
        .await;
    let pom = f
        .store
        .get_path(&BlobId::from_bytes(&pom_text("demo", Some("parent"))));
    let mut writable = fs::metadata(&pom).unwrap().permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    writable.set_readonly(false);
    fs::set_permissions(&pom, writable).unwrap();
    fs::write(&pom, pom_text("demo", Some("other"))).unwrap();
    let failure = f.export().await.expect_err("damaged POM");
    assert!(
        matches!(failure.error, ExportError::CorruptBlob { .. }),
        "{}",
        failure.error
    );
}

/// A `<parent>` whose version is still `${revision}` is not walked: the
/// export ends that branch instead of asking the store for a coordinate
/// Maven would never fetch.
#[tokio::test]
async fn a_parent_with_an_expression_is_not_walked() {
    let mut f = Fixture::new();
    f.row(
        jar("com.example", "demo", "1"),
        b"jar",
        b"<project><parent><groupId>com.example</groupId><artifactId>parent</artifactId>\
          <version>${revision}</version></parent><groupId>com.example</groupId>\
          <artifactId>demo</artifactId><version>1</version></project>",
    )
    .await;
    f.export().await.expect("export");
}

/// A parent named by a version range is exported at the version the lock
/// pins, with the version list `mvn -o` resolves the range from: that of its
/// repository, or the local one when the lock names no repository id.
#[tokio::test]
async fn a_parent_version_range_exports_the_pinned_parent() {
    for (repo_id, listing) in [("central", "central"), ("", "local")] {
        let mut f = Fixture::new();
        let ranged = |artifact_id: &str| {
            String::from_utf8(pom_text(artifact_id, Some("parent")))
                .unwrap()
                .replace(
                    "<version>1</version></parent>",
                    "<version>[1,2)</version></parent>",
                )
                .into_bytes()
        };
        f.row(jar("com.example", "demo", "1"), b"jar", &ranged("demo"))
            .await;
        f.support("com.example:parent:1", repo_id, &pom_text("parent", None))
            .await;
        let project = tempdir().expect("project");
        let path = project.path().join("app");
        fs::write(&path, ranged("app")).unwrap();
        let reactor = Reactor {
            poms: vec![ProjectPom {
                path,
                local_parent: false,
            }],
            ..Reactor::default()
        };
        f.exporter(f.options())
            .export(&reactor)
            .await
            .expect("export");
        assert_eq!(
            f.read("com/example/parent/1/parent-1.pom"),
            String::from_utf8(pom_text("parent", None)).unwrap()
        );
        let metadata = f.read(&format!("com/example/parent/maven-metadata-{listing}.xml"));
        assert!(metadata.contains("<version>1</version>"), "{metadata}");
    }
}

/// A lock row whose repository recorded no id still gets a version list
/// under `maven-metadata-local.xml`, so an offline range that names the
/// artifact can resolve. The `_remote.repositories` marker is omitted.
#[tokio::test]
async fn an_empty_repository_id_lists_the_version_locally() {
    let mut f = Fixture::new();
    f.lock.repo_ids.insert(
        rv_lock::recorded_key(REPO).to_string(),
        [String::new()].into(),
    );
    f.row(jar("com.example", "demo", "1.0.0"), b"jar", b"<project/>")
        .await;
    f.export().await.expect("export");
    let metadata = f.read("com/example/demo/maven-metadata-local.xml");
    assert!(metadata.contains("<version>1.0.0</version>"), "{metadata}");
    assert!(
        !f.m2()
            .join("com/example/demo/1.0.0/_remote.repositories")
            .exists(),
        "empty id must not write a marker file"
    );
}

#[tokio::test]
async fn downloaded_poms_can_have_an_unpinned_reactor_parent() {
    let mut f = Fixture::new();
    f.row(
        jar("com.example", "demo", "1"),
        b"jar",
        &pom_text("demo", Some("reactor-parent")),
    )
    .await;
    let packaged = pom_text("packaged", Some("reactor-parent"));
    f.row(
        LockArtifact::new(support_key("packaged"), REPO),
        &packaged,
        &packaged,
    )
    .await;
    f.support(
        "com.example:bom:1",
        "central",
        &pom_text("bom", Some("reactor-parent")),
    )
    .await;
    let reactor = Reactor {
        modules: BTreeSet::from([Gav::new("com.example", "reactor-parent", "1")]),
        ..Reactor::default()
    };
    let stats = f
        .exporter(f.options())
        .export(&reactor)
        .await
        .expect("export");
    assert_eq!(stats.exported_count, 4);
    for artifact in ["demo", "packaged", "bom"] {
        assert_eq!(
            f.read(&format!("com/example/{artifact}/1/{artifact}-1.pom")),
            String::from_utf8(pom_text(artifact, Some("reactor-parent"))).unwrap()
        );
    }
    assert!(!f.m2().join("com/example/reactor-parent").exists());
}

/// A module's parent that `raeva sync` fetched because the module's
/// `<relativePath>` missed it is exported, although it has a reactor
/// module's coordinate: `mvn -o` resolves that parent from the repository.
#[tokio::test]
async fn a_pinned_parent_with_a_reactor_coordinate_is_exported() {
    let mut f = Fixture::new();
    f.row(
        jar("com.example", "demo", "1"),
        b"jar",
        &pom_text("demo", None),
    )
    .await;
    f.support(
        "com.example:reactor-parent:1",
        "probe",
        &pom_text("reactor-parent", None),
    )
    .await;
    let reactor = Reactor {
        modules: BTreeSet::from([Gav::new("com.example", "reactor-parent", "1")]),
        ..Reactor::default()
    };
    f.exporter(f.options())
        .export(&reactor)
        .await
        .expect("export");
    assert_eq!(
        f.read("com/example/reactor-parent/1/reactor-parent-1.pom"),
        String::from_utf8(pom_text("reactor-parent", None)).unwrap()
    );
}

/// The artifact-level metadata of each repository id lists the versions the
/// lock takes from it and nothing else, and the artifact's other lists,
/// from an online Maven run, `mvn install` or an earlier export, are
/// removed or list nothing: `mvn -o` resolves a range from them.
#[tokio::test]
async fn version_lists_hold_only_the_locked_versions() {
    let other = "https://other.example/maven2/";
    let mut f = Fixture::new();
    // Maven bans only the characters file systems reject from an id.
    for (url, id) in [(REPO, "corp"), (other, "other+releases")] {
        f.lock.repo_ids.insert(
            rv_lock::recorded_key(url).to_string(),
            [id.to_string()].into(),
        );
    }
    f.row(jar("com.example", "demo", "1.5"), b"jar", b"<project/>")
        .await;
    // A support POM is listed too: a range may name a parent, an import or
    // a relocated dependency.
    f.support("com.example:parent:1", "corp", b"<project/>")
        .await;
    let mut from_other = jar("com.example", "demo", "2.0");
    from_other.repo_url = other.to_string();
    f.row(from_other, b"jar 2", b"<project/>").await;
    let dir = f.m2().join("com/example/demo");
    fs::create_dir_all(&dir).unwrap();
    let listing = |versions: &[&str]| {
        let versions: String = versions
            .iter()
            .map(|version| format!("<version>{version}</version>"))
            .collect();
        format!("<metadata><versioning><versions>{versions}</versions></versioning></metadata>")
    };
    for (name, versions) in [
        ("maven-metadata-corp.xml", &["1.5", "3.0"][..]),
        ("maven-metadata-central.xml", &["3.0"]),
        ("maven-metadata-local.xml", &["3.0"]),
    ] {
        fs::write(dir.join(name), listing(versions)).unwrap();
        fs::write(dir.join(format!("{name}.sha1")), "0").unwrap();
    }

    f.export().await.expect("export");
    let versions =
        |id: &str| read_existing_metadata(&dir.join(format!("maven-metadata-{id}.xml"))).versions;
    assert_eq!(versions("corp"), ["1.5"]);
    assert_eq!(versions("other+releases"), ["2.0"]);
    for id in ["central", "local"] {
        assert!(lists_nothing(&dir.join(format!("maven-metadata-{id}.xml"))));
    }
    let parent = f.m2().join("com/example/parent/maven-metadata-corp.xml");
    assert_eq!(read_existing_metadata(&parent).versions, ["1"]);
    let names: BTreeSet<String> = fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        names,
        BTreeSet::from(
            [
                "1.5",
                "2.0",
                "maven-metadata-central.xml",
                "maven-metadata-corp.xml",
                "maven-metadata-local.xml",
                "maven-metadata-other+releases.xml"
            ]
            .map(str::to_string)
        )
    );
}

/// `mvn -o -Dmaven.repo.local.tail=...` reads a version list from the tail
/// wherever the head has none under that id, and an online run leaves lists
/// there that name versions and SNAPSHOT builds the lock does not. So every
/// id the build may read, the lock's, the configured ones, `central` and
/// `local`, gets a list in the head, naming nothing where the lock takes
/// nothing from it, for the artifact and for each SNAPSHOT version.
#[tokio::test]
async fn every_id_the_build_reads_has_a_list() {
    let mut f = Fixture::new();
    f.lock.repo_ids.insert(
        rv_lock::recorded_key(REPO).to_string(),
        ["corp".to_string()].into(),
    );
    f.lock.repo_ids.insert(
        "https://corp2.example/".to_string(),
        ["corp2".to_string()].into(),
    );
    f.row(jar("com.example", "demo", "1.5"), b"jar", b"<project/>")
        .await;
    let mut snapshot = jar("com.example", "snap", "1.0-SNAPSHOT");
    snapshot.snapshot = SnapshotStamp::of_version("1.0-20240101.010101-1");
    f.row(snapshot, b"snap", b"<project/>").await;
    let snapshot_dir = f.m2().join("com/example/snap/1.0-SNAPSHOT");
    fs::create_dir_all(&snapshot_dir).unwrap();
    fs::write(snapshot_dir.join("maven-metadata-corp2.xml"), "<metadata/>").unwrap();
    fs::write(snapshot_dir.join("maven-metadata-corp2.xml.sha1"), "0").unwrap();

    f.export().await.expect("export");
    let dir = f.m2().join("com/example/demo");
    assert_eq!(
        read_existing_metadata(&dir.join("maven-metadata-corp.xml")).versions,
        ["1.5"]
    );
    let corp = read_existing_metadata(&snapshot_dir.join("maven-metadata-corp.xml"));
    assert!(
        (corp.snapshot_versions.iter()).any(|entry| entry.value == "1.0-20240101.010101-1"),
        "{corp:?}"
    );
    for id in ["corp2", "central", "local"] {
        let name = format!("maven-metadata-{id}.xml");
        for dir in [&dir, &f.m2().join("com/example/snap"), &snapshot_dir] {
            assert!(lists_nothing(&dir.join(&name)), "{dir:?} {name}");
        }
    }
    assert!(!snapshot_dir.join("maven-metadata-corp2.xml.sha1").exists());
    let modified = |path: PathBuf| fs::metadata(path).unwrap().modified().unwrap();
    assert_eq!(
        modified(dir.join("maven-metadata-local.xml")),
        std::time::UNIX_EPOCH
    );
    assert_ne!(
        modified(dir.join("maven-metadata-central.xml")),
        std::time::UNIX_EPOCH
    );
    // A list with the right text and another time, as another id that the
    // volume folds onto `local` leaves it, gets the epoch too.
    fs::File::options()
        .write(true)
        .open(dir.join("maven-metadata-local.xml"))
        .unwrap()
        .set_modified(std::time::SystemTime::now())
        .unwrap();
    f.export().await.expect("export again");
    assert_eq!(
        modified(dir.join("maven-metadata-local.xml")),
        std::time::UNIX_EPOCH
    );
}

/// An id that differs from a serving one only in letter case gets its own
/// empty list where the volume tells them apart, and leaves the serving
/// list alone where both name one file.
#[tokio::test]
async fn an_empty_list_does_not_replace_a_list_that_differs_in_case() {
    let mut f = Fixture::new();
    f.lock.repo_ids.insert(
        rv_lock::recorded_key(REPO).to_string(),
        ["Central".to_string()].into(),
    );
    f.row(jar("com.example", "demo", "1.5"), b"jar", b"<project/>")
        .await;
    f.export().await.expect("export");
    let dir = f.m2().join("com/example/demo");
    let versions =
        |id: &str| read_existing_metadata(&dir.join(format!("maven-metadata-{id}.xml"))).versions;
    assert_eq!(versions("Central"), ["1.5"]);
    if super::folds_case(&dir).unwrap() {
        assert_eq!(versions("central"), ["1.5"]);
    } else {
        assert!(lists_nothing(&dir.join("maven-metadata-central.xml")));
    }
}

/// Into the shared Maven local repository, the locked versions are added to
/// each list, and the listings and SNAPSHOT metadata of `mvn install`, an
/// online run or another repository stay.
#[tokio::test]
async fn a_shared_repository_keeps_other_metadata() {
    let mut f = Fixture::new();
    f.lock.repo_ids.insert(
        rv_lock::recorded_key(REPO).to_string(),
        ["corp".to_string()].into(),
    );
    f.row(jar("com.example", "demo", "1.5"), b"jar", b"<project/>")
        .await;
    f.row(
        jar("com.example", "snap", "1.0-SNAPSHOT"),
        b"snap",
        b"<project/>",
    )
    .await;
    let dir = f.m2().join("com/example/demo");
    fs::create_dir_all(&dir).unwrap();
    let listing = |versions: &[&str]| {
        let versions: String = versions
            .iter()
            .map(|version| format!("<version>{version}</version>"))
            .collect();
        format!("<metadata><versioning><versions>{versions}</versions></versioning></metadata>")
    };
    for (name, versions) in [
        ("maven-metadata-corp.xml", &["3.0"][..]),
        ("maven-metadata-local.xml", &["4.0-SNAPSHOT"]),
    ] {
        fs::write(dir.join(name), listing(versions)).unwrap();
        fs::write(dir.join(format!("{name}.sha1")), "0").unwrap();
    }
    let snapshot_dir = f.m2().join("com/example/snap/1.0-SNAPSHOT");
    fs::create_dir_all(&snapshot_dir).unwrap();
    let installed = "<metadata><versioning><snapshot><localCopy>true</localCopy>\
                     </snapshot></versioning></metadata>";
    fs::write(snapshot_dir.join("maven-metadata-local.xml"), installed).unwrap();

    let options = ExportOptions {
        shared: true,
        ..f.options()
    };
    f.exporter(options)
        .export(&Reactor::default())
        .await
        .expect("export");
    let versions =
        |id: &str| read_existing_metadata(&dir.join(format!("maven-metadata-{id}.xml"))).versions;
    assert_eq!(versions("corp"), ["1.5", "3.0"]);
    assert_eq!(versions("local"), ["4.0-SNAPSHOT"]);
    assert!(!dir.join("maven-metadata-central.xml").exists());
    assert!(dir.join("maven-metadata-local.xml.sha1").exists());
    assert!(!dir.join("maven-metadata-corp.xml.sha1").exists());
    assert_eq!(
        f.read("com/example/snap/1.0-SNAPSHOT/maven-metadata-local.xml"),
        installed
    );
}

/// A relocated SNAPSHOT dependency's POM, recorded by its build, is also
/// exported as the plain `-SNAPSHOT` file `mvn -o` reads without snapshot
/// metadata, and its version is listed for a range.
#[tokio::test]
async fn a_timestamped_support_pom_gets_its_plain_file() {
    let mut f = Fixture::new();
    f.row(jar("com.example", "demo", "1.0.0"), b"jar", b"<project/>")
        .await;
    f.support("com.example:moved:1.0-20240101.010101-1", "corp", b"stub")
        .await;
    // An earlier build's metadata would name its own POM, and Maven takes
    // the latest build any repository's metadata names.
    let dir = "com/example/moved/1.0-SNAPSHOT";
    fs::create_dir_all(f.m2().join(dir)).unwrap();
    for (id, build) in [
        ("corp", "20231231.010101-9"),
        ("other", "20250101.010101-3"),
    ] {
        let (timestamp, number) = build.split_once('-').unwrap();
        fs::write(
            f.m2().join(dir).join(format!("maven-metadata-{id}.xml")),
            format!(
                "<metadata><versioning><snapshot><timestamp>{timestamp}</timestamp>\
                 <buildNumber>{number}</buildNumber></snapshot><snapshotVersions>\
                 <snapshotVersion><extension>pom</extension><value>1.0-{build}</value>\
                 <updated>20231231010101</updated></snapshotVersion></snapshotVersions>\
                 </versioning></metadata>"
            ),
        )
        .unwrap();
    }
    f.export().await.expect("export");
    assert!(!f.m2().join(dir).join("maven-metadata-other.xml").exists());
    let snapshot = read_existing_metadata(&f.m2().join(dir).join("maven-metadata-corp.xml"));
    assert_eq!(
        snapshot
            .snapshot_versions
            .iter()
            .map(|entry| (entry.extension.as_str(), entry.value.as_str()))
            .collect::<Vec<_>>(),
        [("pom", "1.0-20240101.010101-1")]
    );
    assert_eq!(
        f.read(&format!("{dir}/moved-1.0-20240101.010101-1.pom")),
        "stub"
    );
    assert_eq!(f.read(&format!("{dir}/moved-1.0-SNAPSHOT.pom")), "stub");
    assert!(
        f.read(&format!("{dir}/_remote.repositories"))
            .contains("moved-1.0-SNAPSHOT.pom>corp=\n")
    );
    let listed = f.m2().join("com/example/moved/maven-metadata-corp.xml");
    assert_eq!(read_existing_metadata(&listed).versions, ["1.0-SNAPSHOT"]);
}

/// A plain `-SNAPSHOT` parent, and a SNAPSHOT a repository serves without
/// builds, replace what an earlier export wrote, as Maven rewrites them on
/// every update. Metadata an earlier run left in their directories would
/// make `mvn -o` take the build it names instead, so it is removed.
#[tokio::test]
async fn plain_snapshot_updates_replace_the_earlier_files() {
    let mut f = Fixture::new();
    let stale = |f: &Fixture, dir: &str| {
        let dir = f.m2().join(dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("maven-metadata-corp.xml"), "<metadata/>").unwrap();
        fs::write(dir.join("maven-metadata-corp.xml.sha1"), "0").unwrap();
        dir
    };
    for bytes in ["one", "two"] {
        f.lock.platforms[0].artifacts.clear();
        f.row(
            jar("com.example", "nu", "1.0-SNAPSHOT"),
            bytes.as_bytes(),
            bytes.as_bytes(),
        )
        .await;
        f.support("com.example:parent:1.0-SNAPSHOT", "corp", bytes.as_bytes())
            .await;
        let dirs = [
            stale(&f, "com/example/parent/1.0-SNAPSHOT"),
            stale(&f, "com/example/nu/1.0-SNAPSHOT"),
        ];
        f.export().await.expect("export");
        assert_eq!(
            f.read("com/example/parent/1.0-SNAPSHOT/parent-1.0-SNAPSHOT.pom"),
            bytes
        );
        assert_eq!(
            f.read("com/example/nu/1.0-SNAPSHOT/nu-1.0-SNAPSHOT.jar"),
            bytes
        );
        assert_eq!(
            f.read("com/example/nu/1.0-SNAPSHOT/nu-1.0-SNAPSHOT.pom"),
            bytes
        );
        for dir in dirs {
            assert!(
                lists_nothing(&dir.join("maven-metadata-corp.xml")),
                "{dir:?}"
            );
            assert!(
                !dir.join("maven-metadata-corp.xml.sha1").exists(),
                "{dir:?}"
            );
        }
    }
}

/// A `-SNAPSHOT` POM the lock pins itself, as a parent, is the plain file
/// even when a build of the same SNAPSHOT is recorded too, and no metadata
/// names that build over it.
#[tokio::test]
async fn a_pinned_snapshot_parent_wins_over_a_recorded_build() {
    let mut f = Fixture::new();
    f.row(jar("com.example", "demo", "1.0.0"), b"jar", b"<project/>")
        .await;
    f.support("com.example:moved:1.0-SNAPSHOT", "corp", b"parent")
        .await;
    f.support("com.example:moved:1.0-20240101.010101-1", "corp", b"stub")
        .await;
    f.export().await.expect("export");
    let dir = f.m2().join("com/example/moved/1.0-SNAPSHOT");
    assert_eq!(
        fs::read(dir.join("moved-1.0-SNAPSHOT.pom")).unwrap(),
        b"parent"
    );
    assert_eq!(
        fs::read(dir.join("moved-1.0-20240101.010101-1.pom")).unwrap(),
        b"stub"
    );
    assert!(lists_nothing(&dir.join("maven-metadata-corp.xml")));
}

/// Of two builds of one relocated SNAPSHOT the lock records, the latest is
/// the one a `-SNAPSHOT` request resolves to, whatever order they are read.
#[tokio::test]
async fn the_latest_relocated_snapshot_build_is_listed() {
    let mut f = Fixture::new();
    f.row(jar("com.example", "demo", "1.0.0"), b"jar", b"<project/>")
        .await;
    f.support("com.example:moved:1.0-20240102.010101-2", "corp", b"two")
        .await;
    f.support("com.example:moved:1.0-20240101.010101-1", "corp", b"one")
        .await;
    f.export().await.expect("export");
    let dir = f.m2().join("com/example/moved/1.0-SNAPSHOT");
    let snapshot = read_existing_metadata(&dir.join("maven-metadata-corp.xml"));
    assert_eq!(
        snapshot
            .snapshot_versions
            .iter()
            .map(|entry| entry.value.as_str())
            .collect::<Vec<_>>(),
        ["1.0-20240102.010101-2"]
    );
    assert_eq!(
        fs::read(dir.join("moved-1.0-SNAPSHOT.pom")).unwrap(),
        b"two"
    );
    assert_eq!(
        fs::read(dir.join("moved-1.0-20240101.010101-1.pom")).unwrap(),
        b"one"
    );
}

/// A snapshot update replaces the plain `-SNAPSHOT` copy an earlier export
/// left, as Maven rewrites it on every update.
#[tokio::test]
async fn a_snapshot_update_replaces_the_plain_copy() {
    let mut f = Fixture::new();
    for (build, bytes) in [
        ("1.0-20240101.010101-1", "one"),
        ("1.0-20240102.020202-2", "two"),
    ] {
        f.lock.platforms[0].artifacts.clear();
        let mut row = jar("com.example", "snap", "1.0-SNAPSHOT");
        row.snapshot = SnapshotStamp::of_version(build);
        f.row(row, bytes.as_bytes(), b"<project/>").await;
        f.export().await.expect("export");
        assert_eq!(
            f.read("com/example/snap/1.0-SNAPSHOT/snap-1.0-SNAPSHOT.jar"),
            bytes
        );
    }
}

#[cfg(unix)]
#[tokio::test]
async fn a_repeated_export_writes_nothing() {
    use std::os::unix::fs::MetadataExt;
    fn inodes(dir: &Path, found: &mut Vec<(PathBuf, u64)>) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                inodes(&path, found);
            } else {
                found.push((path.clone(), fs::metadata(&path).unwrap().ino()));
            }
        }
    }
    let mut f = Fixture::new();
    f.row(jar("com.example", "demo", "1.0.0"), b"jar", b"<project/>")
        .await;
    f.export().await.expect("export");
    let (mut before, mut after) = (Vec::new(), Vec::new());
    inodes(&f.m2(), &mut before);
    let stats = f.export().await.expect("re-export");
    assert_eq!(stats.skipped_count, 2);
    inodes(&f.m2(), &mut after);
    before.sort();
    after.sort();
    assert_eq!(before, after);
}

/// A repeated copying export hashes each copy, so other bytes of the same
/// size and modification time are caught, and writes missing or torn
/// sidecars again.
#[tokio::test]
async fn a_repeated_copy_export_hashes_copies_and_repairs_sidecars() {
    let mut f = Fixture::new();
    f.row(jar("com.example", "demo", "1.0.0"), b"jar", b"<project/>")
        .await;
    f.export().await.expect("export");
    let dir = f.m2().join("com/example/demo/1.0.0");
    let jar_path = dir.join("demo-1.0.0.jar");
    let mtime = fs::metadata(&jar_path).unwrap().modified().unwrap();
    let blob = f.store.get_path(&BlobId::from_bytes(b"jar"));
    assert_eq!(mtime, fs::metadata(&blob).unwrap().modified().unwrap());
    let rewrite = |bytes: &[u8]| {
        fs::write(&jar_path, bytes).unwrap();
        let file = fs::File::options().write(true).open(&jar_path).unwrap();
        file.set_modified(mtime).unwrap();
    };

    rewrite(b"JAR");
    assert!(matches!(
        f.export().await.expect_err("other bytes").error,
        ExportError::DestinationMismatch { .. }
    ));

    rewrite(b"jar");
    fs::remove_file(dir.join("demo-1.0.0.jar.sha1")).unwrap();
    fs::write(dir.join("demo-1.0.0.jar.sha256"), "torn").unwrap();
    assert_eq!(f.export().await.expect("re-export").skipped_count, 2);
    assert_eq!(
        f.read("com/example/demo/1.0.0/demo-1.0.0.jar.sha256"),
        BlobId::from_bytes(b"jar").as_str()
    );
    assert_eq!(
        f.read("com/example/demo/1.0.0/demo-1.0.0.jar.sha1"),
        "f92e777f4341930bad9b2422283c4680d00dbc06"
    );
}

/// A repeated linking export takes a link unread only while the store shows
/// no write to the blob, so bytes changed through the link are caught.
#[tokio::test]
async fn a_write_through_a_link_fails_the_repeated_export() {
    let mut f = Fixture::new();
    f.row(jar("com.example", "demo", "1.0.0"), b"jar", b"<project/>")
        .await;
    let mut options = f.options();
    options.link_strategy = LinkStrategy::Hardlink;
    let export = || async {
        f.exporter(options.clone())
            .export(&Reactor::default())
            .await
    };
    export().await.expect("export");
    assert_eq!(export().await.expect("re-export").skipped_count, 2);
    let jar_path = f.m2().join("com/example/demo/1.0.0/demo-1.0.0.jar");
    let mut writable = fs::metadata(&jar_path).unwrap().permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    writable.set_readonly(false);
    fs::set_permissions(&jar_path, writable).unwrap();
    fs::write(&jar_path, b"JAR").unwrap();
    let failure = export().await.expect_err("changed blob");
    assert!(
        matches!(failure.error, ExportError::CorruptBlob { .. }),
        "{}",
        failure.error
    );
}

/// `--overwrite` must clear a directory that occupies the artifact path.
/// `rename` cannot replace a directory with a file, so leaving it would
/// make overwrite fail after writing sidecars beside the directory.
#[tokio::test]
async fn overwrite_replaces_a_directory_at_the_artifact_path() {
    let mut f = Fixture::new();
    f.row(jar("com.example", "demo", "1.0.0"), b"jar", b"<project/>")
        .await;
    let jar_path = f.m2().join("com/example/demo/1.0.0/demo-1.0.0.jar");
    fs::create_dir_all(&jar_path).unwrap();
    fs::write(jar_path.join("noise"), "x").unwrap();
    let failure = f.export().await.expect_err("directory without overwrite");
    assert!(
        matches!(failure.error, ExportError::DestinationMismatch { .. }),
        "{failure}"
    );
    let mut options = f.options();
    options.overwrite = true;
    f.exporter(options)
        .export(&Reactor::default())
        .await
        .expect("overwrite directory");
    assert!(
        jar_path.is_file(),
        "artifact path must be a file after overwrite"
    );
    assert_eq!(f.read("com/example/demo/1.0.0/demo-1.0.0.jar"), "jar");
}

/// A destination symlink that points outside the store, even when its
/// target currently hashes to the locked blob, must be replaced. Leaving
/// it would let later writes to that foreign path change what `mvn -o`
/// reads without the store noticing.
#[cfg(unix)]
#[tokio::test]
async fn a_foreign_symlink_with_matching_bytes_is_replaced() {
    let mut f = Fixture::new();
    f.row(jar("com.example", "demo", "1.0.0"), b"jar", b"<project/>")
        .await;
    let jar_path = f.m2().join("com/example/demo/1.0.0/demo-1.0.0.jar");
    fs::create_dir_all(jar_path.parent().unwrap()).unwrap();
    let outside = f.m2_dir.path().join("foreign-jar");
    fs::write(&outside, b"jar").unwrap();
    std::os::unix::fs::symlink(&outside, &jar_path).unwrap();
    let blob = f.store.get_path(&BlobId::from_bytes(b"jar"));

    for strategy in [
        LinkStrategy::Hardlink,
        LinkStrategy::Symlink,
        LinkStrategy::Copy,
    ] {
        let _ = fs::remove_file(&jar_path);
        std::os::unix::fs::symlink(&outside, &jar_path).unwrap();
        let mut options = f.options();
        options.link_strategy = strategy;
        f.exporter(options)
            .export(&Reactor::default())
            .await
            .unwrap_or_else(|err| panic!("{strategy}: {err}"));
        let meta = fs::symlink_metadata(&jar_path).unwrap();
        assert!(
            !meta.file_type().is_symlink() || same_file::is_same_file(&jar_path, &blob).unwrap(),
            "{strategy}: destination must not keep the foreign symlink"
        );
        assert_eq!(f.read("com/example/demo/1.0.0/demo-1.0.0.jar"), "jar");
    }
}

/// A destination hard-linked to a file outside the store, even when those
/// bytes currently match the locked blob, must be replaced. Leaving the
/// shared inode would let later writes to that foreign path change what
/// `mvn -o` reads without the store noticing.
#[cfg(unix)]
#[tokio::test]
async fn a_foreign_hardlink_with_matching_bytes_is_replaced() {
    let mut f = Fixture::new();
    f.row(jar("com.example", "demo", "1.0.0"), b"jar", b"<project/>")
        .await;
    let jar_path = f.m2().join("com/example/demo/1.0.0/demo-1.0.0.jar");
    fs::create_dir_all(jar_path.parent().unwrap()).unwrap();
    let outside = f.m2_dir.path().join("foreign-jar");
    fs::write(&outside, b"jar").unwrap();
    let blob = f.store.get_path(&BlobId::from_bytes(b"jar"));

    for strategy in [
        LinkStrategy::Hardlink,
        LinkStrategy::Symlink,
        LinkStrategy::Copy,
    ] {
        let _ = fs::remove_file(&jar_path);
        fs::write(&outside, b"jar").unwrap();
        fs::hard_link(&outside, &jar_path).unwrap();
        assert!(
            !same_file::is_same_file(&jar_path, &blob).unwrap(),
            "precondition: destination must not already share the store blob"
        );
        let mut options = f.options();
        options.link_strategy = strategy;
        f.exporter(options)
            .export(&Reactor::default())
            .await
            .unwrap_or_else(|err| panic!("{strategy}: {err}"));
        assert!(
            !same_file::is_same_file(&jar_path, &outside).unwrap(),
            "{strategy}: destination must not keep the foreign hardlink"
        );
        assert_eq!(f.read("com/example/demo/1.0.0/demo-1.0.0.jar"), "jar");
        fs::write(&outside, b"tampered").unwrap();
        assert_eq!(
            f.read("com/example/demo/1.0.0/demo-1.0.0.jar"),
            "jar",
            "{strategy}: a write to the foreign path must not change the export"
        );
    }
}

/// Links an earlier export left are kept by a linking export and replaced
/// by a copying one, which never writes through them into the store.
#[tokio::test]
async fn links_an_earlier_export_left_are_kept_or_replaced() {
    let mut f = Fixture::new();
    f.row(jar("com.example", "demo", "1.0.0"), b"jar", b"<project/>")
        .await;
    let jar_path = f.m2().join("com/example/demo/1.0.0/demo-1.0.0.jar");
    let f = &f;
    let export = |strategy| {
        let mut options = f.options();
        options.link_strategy = strategy;
        async move {
            f.exporter(options)
                .export(&Reactor::default())
                .await
                .expect("export")
        }
    };
    // Windows needs a privilege for symbolic links.
    let strategies: &[LinkStrategy] = if cfg!(unix) {
        &[LinkStrategy::Symlink, LinkStrategy::Hardlink]
    } else {
        &[LinkStrategy::Hardlink]
    };
    let blob = f.store.get_path(&BlobId::from_bytes(b"jar"));
    for &strategy in strategies {
        let _ = fs::remove_dir_all(f.m2());
        assert_eq!(export(strategy).await.exported_count, 2, "{strategy}");
        assert_eq!(export(strategy).await.skipped_count, 2, "{strategy}");
        assert_eq!(
            export(LinkStrategy::Copy).await.copied_count,
            2,
            "{strategy}"
        );
        assert!(
            fs::symlink_metadata(&jar_path).unwrap().is_file(),
            "{strategy}"
        );
        assert!(
            !same_file::is_same_file(&jar_path, &blob).unwrap(),
            "{strategy}"
        );
        assert_eq!(f.read("com/example/demo/1.0.0/demo-1.0.0.jar"), "jar");
    }
}

#[tokio::test]
async fn a_parent_absent_from_support_pins_is_not_taken_from_the_index() {
    let mut f = Fixture::new();
    f.row(
        jar("com.example", "demo", "1"),
        b"jar",
        &pom_text("demo", Some("parent")),
    )
    .await;
    f.put(&support_key("parent"), b"another repository's parent")
        .await;
    let err = f.refused().await;
    assert!(
        matches!(&err, ExportError::UnpinnedPom { coordinate } if coordinate == "com.example:parent:1"),
        "{err}"
    );
}

/// Each record pins the bytes of one Maven path; when two disagree, or the
/// pinned bytes are gone, the export fails before anything is written.
#[tokio::test]
async fn pins_that_disagree_or_are_missing_fail_before_writing() {
    async fn demo() -> Fixture {
        let mut f = Fixture::new();
        f.row(jar("com.example", "demo", "1.0.0"), b"jar", b"pom")
            .await;
        f
    }
    let absent = BlobId::from_bytes(b"absent");

    let mut f = demo().await;
    f.support("com.example:demo:1.0.0", "central", b"other pom")
        .await;
    let err = f.refused().await;
    assert!(
        matches!(err, ExportError::ConflictingExportSources { .. }),
        "{err}"
    );

    let mut f = demo().await;
    f.lock.platforms[0].support_poms.insert(
        "com.example:gone:1".to_string(),
        SupportPom::new("https://central.example/", absent.clone()),
    );
    let err = f.refused().await;
    assert!(matches!(err, ExportError::MissingPinnedPom { .. }), "{err}");

    let mut f = demo().await;
    f.lock.platforms[0].artifacts[0].pom_sha256 = Some(absent.clone());
    let err = f.refused().await;
    assert!(matches!(err, ExportError::MissingPinnedPom { .. }), "{err}");

    // A stored file the index does not name for a row stands in for it only
    // when a repository served it for that row.
    let mut f = demo().await;
    let row = &mut f.lock.platforms[0].artifacts[0];
    row.coordinate = ArtifactCoord::new("com.example", "demo", "0.9.0", "jar", None);
    let err = f.refused().await;
    assert!(matches!(err, ExportError::MissingBlob { .. }), "{err}");

    let f = demo().await;
    let key = f.lock.platforms[0].artifacts[0].coord();
    let origin = rv_store::Origin {
        repo_url: REPO.into(),
        endpoint_url: REPO.into(),
        checksum_verified: true,
        served: true,
    };
    let served = vec![(key.clone(), BlobId::from_bytes(b"jar"), origin)];
    f.store.record_origins(served).await.unwrap();
    f.put_from(&key, b"another repository's jar", "https://other.example/")
        .await;
    f.export()
        .await
        .expect("the pinned blob wins over the index");
    assert_eq!(f.read("com/example/demo/1.0.0/demo-1.0.0.jar"), "jar");

    // Another project sharing the store indexed other bytes for the row.
    for (algorithm, digest) in [
        ("sha256", BlobId::from_bytes(b"other").to_string()),
        ("sha1", hex::encode(Sha1::digest(b"other"))),
    ] {
        let mut f = demo().await;
        f.lock.platforms[0].artifacts[0].checksums =
            vec![Digest::parse(algorithm, &digest).unwrap()];
        let err = f.refused().await;
        assert!(
            matches!(&err, ExportError::PinMismatch { algorithm: a, .. } if a == algorithm),
            "{err}"
        );
    }

    // Nor do bytes only a repository neither configured nor recorded for the
    // row served, as another project's may have, though the index names them.
    let mut f = demo().await;
    let key = f.lock.platforms[0].artifacts[0].coord();
    let foreign = f.store.put_bytes(b"another project's jar").await.unwrap();
    f.store.add_artifact(&key, &foreign).await.unwrap();
    let origin = rv_store::Origin {
        repo_url: "https://foreign.example/".into(),
        endpoint_url: "https://foreign.example/".into(),
        checksum_verified: true,
        served: true,
    };
    let served = vec![(key.clone(), foreign.clone(), origin)];
    f.store.record_origins(served).await.unwrap();
    f.lock.platforms[0].artifacts[0].checksums = vec![Digest::Sha256(foreign)];
    let err = f.refused().await;
    assert!(matches!(err, ExportError::MissingBlob { .. }), "{err}");

    // So for a companion POM and a support POM: a pin edited to name a
    // POM only another project's repository served, its graph digests
    // recomputed, does not export it.
    async fn foreign_pom(store: &Store, key: ArtifactCoord) -> BlobId {
        let origin = rv_store::Origin {
            repo_url: "https://foreign.example/".into(),
            endpoint_url: "https://foreign.example/".into(),
            checksum_verified: true,
            served: true,
        };
        let blob = store
            .put_bytes(b"<project><!-- foreign --></project>")
            .await
            .unwrap();
        store
            .record_origins(vec![(key, blob.clone(), origin)])
            .await
            .unwrap();
        blob
    }
    let mut f = demo().await;
    let row = &f.lock.platforms[0].artifacts[0];
    let pom = foreign_pom(&f.store, ArtifactCoord::of(row.pom_gav(), "pom", None)).await;
    f.lock.platforms[0].artifacts[0].pom_sha256 = Some(pom);
    let err = f.refused().await;
    assert!(matches!(err, ExportError::MissingPinnedPom { .. }), "{err}");
    let mut f = Fixture::new();
    let pom = pom_text("demo", Some("parent"));
    f.row(jar("com.example", "demo", "1.0.0"), b"jar", &pom)
        .await;
    f.support("com.example:parent:1", "central", &pom_text("parent", None))
        .await;
    f.export().await.expect("the served parent exports");
    // Platforms can record a parent under different repositories; the one
    // that served it stands for every platform.
    let mut f = Fixture::new();
    f.row(jar("com.example", "demo", "1.0.0"), b"jar", &pom)
        .await;
    f.support("com.example:parent:1", "other", &pom_text("parent", None))
        .await;
    let mut first = f.lock.platforms[0].clone();
    first.platform = Platform::new("macos", "aarch64").unwrap();
    let pin = first.support_poms.get_mut("com.example:parent:1").unwrap();
    pin.repo_url = "https://central.example/".into();
    f.lock.platforms.insert(0, first);
    f.export()
        .await
        .expect("the parent another platform's repository served exports");
    let mut f = Fixture::new();
    f.row(jar("com.example", "demo", "1.0.0"), b"jar", &pom)
        .await;
    f.support("com.example:parent:1", "central", &pom_text("parent", None))
        .await;
    let pom = foreign_pom(&f.store, support_key("parent")).await;
    let support = f.lock.platforms[0]
        .support_poms
        .get_mut("com.example:parent:1");
    support.unwrap().sha256 = pom;
    let err = f.refused().await;
    assert!(matches!(err, ExportError::MissingPinnedPom { .. }), "{err}");

    // Without an indexed blob, only a SHA-256 pin can address one.
    let mut f = demo().await;
    let row = &mut f.lock.platforms[0].artifacts[0];
    row.coordinate = ArtifactCoord::new("com.example", "unindexed", "1.0.0", "jar", None);
    row.checksums = vec![Digest::parse("sha1", &hex::encode(Sha1::digest(b"jar"))).unwrap()];
    let err = f.refused().await;
    assert!(
        matches!(err, ExportError::UnsupportedChecksum { .. }),
        "{err}"
    );
    f.lock.platforms[0].artifacts[0].checksums =
        vec![Digest::parse("sha256", absent.as_str()).unwrap()];
    let err = f.refused().await;
    assert!(matches!(err, ExportError::MissingBlob { .. }), "{err}");

    // For packaging=pom the artifact and its POM are one file.
    let mut f = Fixture::new();
    let mut pom_row = LockArtifact::new(support_key("bom"), REPO);
    let payload = f.put(&pom_row.coord(), b"payload").await;
    pom_row.checksums = vec![Digest::parse("sha256", payload.as_str()).unwrap()];
    pom_row.pom_sha256 = Some(f.store.put_bytes(b"companion").await.unwrap());
    f.lock.platforms[0].artifacts.push(pom_row);
    let err = f.refused().await;
    assert!(
        matches!(err, ExportError::ConflictingPomPackagedPin { .. }),
        "{err}"
    );
}

/// The closure limit counts unique POMs, not references, and a run over it
/// fails instead of writing a partial closure. An unusable override keeps
/// the default and is reported once.
#[tokio::test]
async fn the_support_pom_limit_counts_unique_poms() {
    let mut f = Fixture::new();
    for artifact in ["a", "b"] {
        f.row(
            jar("com.example", artifact, "1.0.0"),
            artifact.as_bytes(),
            &pom_text(artifact, Some("shared")),
        )
        .await;
    }
    f.support("com.example:shared:1", "central", &pom_text("shared", None))
        .await;
    let mut exporter = f.exporter(f.options());
    exporter.max_support_pom_nodes = 1;
    exporter
        .export(&Reactor::default())
        .await
        .expect("one unique support POM");

    f.support(
        "com.example:shared:1",
        "central",
        &pom_text("shared", Some("top")),
    )
    .await;
    f.support("com.example:top:1", "central", b"top").await;
    let mut exporter = f.exporter(f.options());
    exporter.max_support_pom_nodes = 1;
    let failure = exporter
        .export(&Reactor::default())
        .await
        .expect_err("two unique support POMs");
    assert!(
        matches!(
            failure.error,
            ExportError::SupportClosureTooLarge { limit: 1, .. }
        ),
        "{failure}"
    );

    let mut options = f.options();
    options.dry_run = true;
    let exporter = f.exporter(options).with_support_pom_limit(Some("0"));
    assert_eq!(exporter.max_support_pom_nodes, super::MAX_SUPPORT_POM_NODES);
    let limit_warnings = |stats: ExportStats| {
        stats
            .warnings
            .into_iter()
            .filter(|warning| matches!(warning, ExportWarning::SupportPomLimitIgnored { .. }))
            .count()
    };
    let first = exporter.export(&Reactor::default()).await.expect("export");
    assert_eq!(limit_warnings(first), 1);
    let second = exporter.export(&Reactor::default()).await.expect("export");
    assert_eq!(limit_warnings(second), 0);
}

#[tokio::test]
async fn a_failure_returns_the_warnings_found_before_it() {
    let mut f = Fixture::new();
    f.row(
        jar("com.example", "demo", "1.0.0"),
        b"jar",
        &pom_text("demo", None),
    )
    .await;
    let mut local = LockModulePackage::new(
        ArtifactCoord::new("com.example", "local", "1", "jar", None),
        Some(Scope::System),
    );
    local.system_path = Some("lib/local.jar".to_string());
    f.lock.platforms[0].modules[0].packages.push(local);
    let jar_path = f.m2().join("com/example/demo/1.0.0/demo-1.0.0.jar");
    fs::create_dir_all(jar_path.parent().unwrap()).unwrap();
    fs::write(&jar_path, "other").unwrap();

    let failure = f
        .export()
        .await
        .expect_err("the destination holds other bytes");
    assert!(
        matches!(failure.error, ExportError::DestinationMismatch { .. }),
        "{failure}"
    );
    assert_eq!(
        failure.warnings,
        [ExportWarning::SystemScopedSkipped {
            coordinates: vec!["com.example:local:1".to_string()]
        },]
    );
}

#[tokio::test]
async fn a_dry_run_writes_nothing() {
    let mut f = Fixture::new();
    f.row(jar("com.example", "demo", "1.0.0"), b"jar", b"pom")
        .await;
    let mut options = f.options();
    options.dry_run = true;
    options.link_strategy = LinkStrategy::Hardlink;
    let stats = f
        .exporter(options)
        .export(&Reactor::default())
        .await
        .expect("dry run");
    assert_eq!((stats.exported_count, stats.linked_count), (2, 2));
    assert!(!f.m2().exists());
}

/// Every coordinate field is checked with the rule raeva.lock is read with, and
/// a segment Windows would rewrite or alias is refused on every platform.
#[test]
fn coordinates_that_could_escape_or_alias_are_refused() {
    let path = |group, artifact, version, extension, classifier| {
        artifact_relative_path(&ArtifactCoord::new(
            group, artifact, version, extension, classifier,
        ))
    };
    for (group, artifact, version, extension, classifier) in [
        ("../../etc", "passwd", "1.0.0", "jar", None),
        ("com/example", "demo", "1.0.0", "jar", None),
        ("com.example", "demo\\..\\etc", "1.0.0", "jar", None),
        ("com.example", "demo", "../../../etc", "jar", None),
        ("com.example", "demo", "1.0.0", "../evil", None),
        ("com.example", "demo", "1.0.0", "jar", Some("foo/bar")),
        ("com.example", "caf\u{e9}", "1.0.0", "jar", None),
    ] {
        let err = path(group, artifact, version, extension, classifier).expect_err(artifact);
        assert!(matches!(err, ExportError::InvalidCoordinate(_)), "{err}");
    }
    for (artifact, version) in [
        ("con", "1.0"),
        ("NUL", "1.0"),
        ("aux.d", "1.0"),
        ("demo", "Nul.1"),
    ] {
        let err = path("com.example", artifact, version, "jar", None).expect_err(artifact);
        assert!(
            matches!(err, ExportError::WindowsUnsafeName { .. }),
            "{err}"
        );
    }
    for version in ["LONGER~2", "REL~10", "1~1"] {
        let err = path("com.example", "demo", version, "jar", None).expect_err(version);
        assert!(matches!(err, ExportError::ShortNameAlias { .. }), "{err}");
    }
    for (artifact, version) in [("con-utils", "1.0"), ("COM10", "1.0"), ("demo", "1.0~1")] {
        path("com.example", artifact, version, "jar", None).expect(artifact);
    }
    assert_eq!(
        lexical_normalize(Path::new("/m2/com/./example/../escape")),
        Path::new("/m2/com/escape")
    );
}

#[cfg(unix)]
#[test]
fn a_symlinked_directory_cannot_lead_out_of_the_destination() {
    let f = Fixture::new();
    let outside = tempdir().expect("outside");
    fs::create_dir_all(f.m2()).unwrap();
    std::os::unix::fs::symlink(outside.path(), f.m2().join("com")).unwrap();
    let key = ArtifactCoord::new("com.example", "demo", "1.0.0", "jar", None);
    let err = super::safe_artifact_path(&f.options(), &key).expect_err("escapes the destination");
    assert!(matches!(err, ExportError::PathTraversal(_)), "{err}");
}

/// The metadata writers and cleaners refuse a directory that a link leads
/// out of the destination, as artifact paths do.
#[cfg(unix)]
#[test]
fn metadata_is_not_written_or_removed_through_a_link_out_of_the_destination() {
    let f = Fixture::new();
    let outside = tempdir().expect("outside");
    let version = outside.path().join("example/demo/1.0");
    fs::create_dir_all(&version).unwrap();
    fs::write(version.join("maven-metadata-corp.xml"), "<metadata/>").unwrap();
    fs::write(
        outside.path().join("example/demo/maven-metadata-corp.xml"),
        "<metadata/>",
    )
    .unwrap();
    fs::create_dir_all(f.m2()).unwrap();
    std::os::unix::fs::symlink(outside.path(), f.m2().join("com")).unwrap();

    let err = super::remove_version_metadata(
        &f.m2(),
        "com.example",
        "demo",
        "1.0",
        &std::collections::HashSet::new(),
    )
    .expect_err("escapes the destination");
    assert!(matches!(err, ExportError::PathTraversal(_)), "{err}");
    let key = crate::metadata::ArtifactMetaKey {
        group_id: "com.example".to_string(),
        artifact_id: "demo".to_string(),
    };
    let mut state = crate::metadata::ArtifactMetaState::default();
    state.add_version("2.0");
    let mut by_repo = std::collections::BTreeMap::from([("other".to_string(), state)]);
    let err = super::write_artifact_metadata_blocking(
        &f.m2(),
        &key,
        &mut by_repo,
        &std::collections::HashSet::new(),
        false,
    )
    .expect_err("escapes the destination");
    assert!(matches!(err, ExportError::PathTraversal(_)), "{err}");

    assert!(version.join("maven-metadata-corp.xml").exists());
    assert!(
        outside
            .path()
            .join("example/demo/maven-metadata-corp.xml")
            .exists()
    );
    assert!(
        !outside
            .path()
            .join("example/demo/maven-metadata-other.xml")
            .exists()
    );
}

/// Files and artifact or version directories that differ only in case
/// collide; group directories hold no files, so they may.
#[test]
fn case_collisions_cover_files_and_shared_directories() {
    let unit = |group: &str, artifact: &str, version: &str| ExportUnit {
        key: ArtifactCoord::new(group, artifact, version, "jar", None),
        blob: BlobId::from_bytes(version.as_bytes()),
        source: UnitSource::Package,
        repo_ids: vec!["central".to_string()],
        repo_id_recorded: false,
        replace: false,
    };
    let collision = |units: &[ExportUnit]| match planned_destinations(
        units,
        &[],
        &crate::metadata::MetadataAccumulator::default(),
        true,
    ) {
        Err(ExportError::CaseCollision { path, .. }) => Some(path),
        Ok(_) => None,
        Err(err) => panic!("{err}"),
    };
    assert_eq!(
        collision(&[
            unit("com.Example", "lib", "1"),
            unit("com.example", "lib", "2")
        ]),
        Some(PathBuf::from("com/example/lib"))
    );
    assert_eq!(
        collision(&[
            unit("com.example", "Lib", "1"),
            unit("com.example", "lib", "1")
        ]),
        Some(PathBuf::from("com/example/lib"))
    );
    assert_eq!(
        collision(&[unit("org.Acme", "a", "1"), unit("org.acme", "b", "1")]),
        None
    );
    for units in [
        [unit("org.Acme", "a", "1"), unit("org", "acme", "1")],
        [unit("org", "acme", "1"), unit("org.Acme", "a", "1")],
    ] {
        assert_eq!(collision(&units), None);
    }
    assert_eq!(
        collision(&[
            unit("com.example", "lib", "1"),
            unit("com.example", "lib", "2")
        ]),
        None
    );
}

#[tokio::test]
async fn a_case_only_collision_is_refused_where_the_file_system_folds_case() {
    let mut f = Fixture::new();
    for name in ["Foo", "foo"] {
        f.row(jar("com.example", name, "1.0"), name.as_bytes(), b"pom")
            .await;
    }
    fs::create_dir_all(f.m2_dir.path()).unwrap();
    if folds_case(f.m2_dir.path()).expect("probe") {
        let err = f.refused().await;
        assert!(matches!(err, ExportError::CaseCollision { .. }), "{err}");
    } else {
        f.export()
            .await
            .expect("a case-sensitive file system holds both");
        assert_eq!(f.read("com/example/Foo/1.0/Foo-1.0.jar"), "Foo");
        assert_eq!(f.read("com/example/foo/1.0/foo-1.0.jar"), "foo");
    }
}

#[test]
fn equivalent_repository_ids_collide_where_the_volume_merges_them() {
    // Unicode normalization merges the first pair on macOS and on a volume
    // that folds case; lowercase, uppercase or Unicode case folding, of the
    // name or its NFD form, merges the others there.
    for (pair, merged_on_macos) in [
        (["\u{e9}", "e\u{301}"], true),
        (["\u{3c3}", "\u{3c2}"], false),
        (["\u{df}", "\u{1e9e}"], false),
        (["ss", "\u{1e9e}"], false),
        (["ss", "\u{df}"], false),
        (
            [
                "\u{3b1}\u{345}\u{301}\u{3c2}",
                "\u{3b1}\u{301}\u{345}\u{3c3}",
            ],
            false,
        ),
    ] {
        for folds_case in [false, true] {
            for populated in [0, 1, 2] {
                let mut meta = crate::metadata::MetadataAccumulator::default();
                let key = crate::metadata::ArtifactMetaKey {
                    group_id: "org.test".to_string(),
                    artifact_id: "lib".to_string(),
                };
                meta.artifacts.entry(key.clone()).or_default();
                for (index, (id, version)) in pair.into_iter().zip(["1", "2"]).enumerate() {
                    if index >= populated {
                        meta.empty_list_ids.insert(id.to_string());
                        continue;
                    }
                    meta.artifacts
                        .entry(key.clone())
                        .or_default()
                        .entry(id.to_string())
                        .or_default()
                        .add_version(version);
                }
                let planned = planned_destinations(&[], &[], &meta, folds_case);
                // An empty list gives way to a list its id lowercases alike.
                let gives_way = populated < 2 && pair[0].to_lowercase() == pair[1].to_lowercase();
                if !(folds_case || merged_on_macos && cfg!(target_os = "macos"))
                    || folds_case && gives_way
                {
                    assert!(planned.is_ok(), "{pair:?} stay apart");
                    continue;
                }
                let error = match planned {
                    Err(error) => error,
                    Ok(_) => panic!("{pair:?} must collide"),
                };
                assert!(
                    matches!(
                        error,
                        ExportError::DestinationCollision { .. }
                            | ExportError::CaseCollision { .. }
                    ),
                    "{error}"
                );
            }
        }
    }
}

/// `g.a:1-SNAPSHOT`'s version list and `g:a:1-SNAPSHOT`'s build metadata
/// are both `g/a/1-SNAPSHOT/maven-metadata-repo.xml`.
#[test]
fn an_artifact_list_and_snapshot_metadata_in_one_directory_collide() {
    let mut meta = crate::metadata::MetadataAccumulator::default();
    let key = crate::metadata::ArtifactMetaKey {
        group_id: "g.a".to_string(),
        artifact_id: "1-SNAPSHOT".to_string(),
    };
    (meta.artifacts.entry(key).or_default())
        .entry("repo".to_string())
        .or_default()
        .add_version("2");
    let snapshot = crate::metadata::SnapshotMetaKey {
        group_id: "g".to_string(),
        artifact_id: "a".to_string(),
        base_version: "1-SNAPSHOT".to_string(),
        repo_id: "repo".to_string(),
    };
    meta.snapshots.entry(snapshot).or_default().timestamp = Some("20240101.010101".to_string());
    for folds_case in [false, true] {
        let error = planned_destinations(&[], &[], &meta, folds_case)
            .err()
            .expect("one file for two lists");
        assert!(
            matches!(error, ExportError::DestinationCollision { .. }),
            "{error}"
        );
    }
}

#[tokio::test]
async fn optional_snapshot_classifiers_claim_timestamped_and_plain_sidecars() {
    for timestamped in [false, true] {
        for dry_run in [false, true] {
            let mut f = Fixture::new();
            let mut row = jar("g", "a", "1-SNAPSHOT");
            row.snapshot = SnapshotStamp::of_version("1-20240101.010101-1");
            let mut sources = row.clone();
            sources.coordinate = ArtifactCoord::new("g", "a", "1-SNAPSHOT", "jar", Some("sources"));
            f.row(row, b"jar", b"pom").await;
            let mut collision = sources.clone();
            collision.coordinate =
                ArtifactCoord::new("g", "a", "1-SNAPSHOT", "jar.sha256", Some("sources"));
            if !timestamped {
                collision.snapshot = None;
            }
            f.row(collision, b"locked bytes", b"pom").await;
            let exporter = f
                .exporter(ExportOptions {
                    dry_run,
                    ..f.options()
                })
                .with_optional_classifiers(&[sources]);
            let failure = exporter.export(&Reactor::default()).await.unwrap_err();
            let version = if timestamped {
                "1-20240101.010101-1"
            } else {
                "1-SNAPSHOT"
            };
            assert!(
                matches!(&failure.error, ExportError::DestinationCollision { path, .. }
                    if *path == f.m2().join(format!("g/a/1-SNAPSHOT/a-{version}-sources.jar.sha256"))),
                "{failure}"
            );
            assert!(!f.m2().exists(), "written before refusing: {failure}");
        }
    }
}

/// The dry-run probe looks names up instead of writing one, and swaps only
/// ASCII letters: `ß` uppercases to `SS`, another name everywhere.
#[test]
fn the_read_only_case_probe_agrees_with_the_writing_probe() {
    let dir = tempdir().expect("dir");
    let named = dir.path().join("Probe-Dir");
    fs::create_dir(&named).unwrap();
    fs::write(named.join("stra\u{df}e"), b"").unwrap();
    fs::write(named.join("Entry"), b"").unwrap();
    let folds = folds_case(&named).expect("probe");
    assert_eq!(folds_case_without_writing(&named), folds);
    if !folds {
        fs::write(named.join("eNTRY"), b"").unwrap();
        assert!(!folds_case_without_writing(&named));
    }

    // Nothing inside to look up: unknown, so assume the worst.
    let empty = dir.path().join("Empty");
    fs::create_dir(&empty).unwrap();
    assert!(folds_case_without_writing(&empty));
}

/// Two exports of different pins into one local repository take turns: one
/// writes the file, the other refuses it, and the checksums beside it are
/// its own.
#[tokio::test(flavor = "multi_thread")]
async fn concurrent_exports_keep_one_file_with_its_checksums() {
    for round in 0..20 {
        let mut fixtures = [Fixture::new(), Fixture::new()];
        for (fixture, payload) in fixtures.iter_mut().zip([&b"first"[..], b"second"]) {
            let pom = pom_text("a", None);
            fixture.row(jar("g", "a", "1"), payload, &pom).await;
        }
        let [first, second] = &fixtures;
        let shared = || ExportOptions {
            m2_path: first.m2(),
            ..first.options()
        };
        let (first, second) = (first.exporter(shared()), second.exporter(shared()));
        let reactor = Reactor::default();
        let (a, b) = tokio::join!(first.export(&reactor), second.export(&reactor));
        assert!(a.is_ok() != b.is_ok(), "round {round}: {a:?} {b:?}");
        let jar = fixtures[0].m2().join("g/a/1/a-1.jar");
        let written = BlobId::from_bytes(&fs::read(&jar).unwrap());
        let sidecar = fs::read_to_string(format!("{}.sha256", jar.display())).unwrap();
        assert_eq!(sidecar, written.as_str());
    }
}

/// Files a project or another tool left in the destination are read only
/// as regular files of bounded size: a jar, a checksum file or a
/// `_remote.repositories` that links to a device would otherwise hang the
/// export or fill memory.
#[cfg(unix)]
#[tokio::test]
async fn links_to_devices_in_the_destination_are_not_read() {
    let mut f = Fixture::new();
    f.row(jar("com.example", "demo", "1.0.0"), b"jar", b"<project/>")
        .await;
    let dir = f.m2().join("com/example/demo/1.0.0");
    fs::create_dir_all(&dir).unwrap();
    let jar_path = dir.join("demo-1.0.0.jar");
    std::os::unix::fs::symlink("/dev/zero", &jar_path).unwrap();
    let mut options = f.options();
    options.overwrite = true;
    let exported = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        f.exporter(options).export(&Reactor::default()),
    )
    .await
    .expect("the export reads no device");
    exported.expect("replaced");
    assert_eq!(f.read("com/example/demo/1.0.0/demo-1.0.0.jar"), "jar");

    for name in [
        "demo-1.0.0.jar.sha256",
        "demo-1.0.0.jar.sha1",
        "_remote.repositories",
    ] {
        let _ = fs::remove_file(dir.join(name));
        std::os::unix::fs::symlink("/dev/zero", dir.join(name)).unwrap();
    }
    tokio::time::timeout(std::time::Duration::from_secs(20), f.export())
        .await
        .expect("the export reads no device")
        .expect("repaired");
    for name in [
        "demo-1.0.0.jar.sha256",
        "demo-1.0.0.jar.sha1",
        "_remote.repositories",
    ] {
        assert!(
            fs::symlink_metadata(dir.join(name)).unwrap().is_file(),
            "{name}"
        );
    }
    assert_eq!(
        f.read("com/example/demo/1.0.0/demo-1.0.0.jar.sha256"),
        BlobId::from_bytes(b"jar").as_str()
    );
}

/// Anything but a regular file at the export lock's name is refused: a
/// dangling link would create a file wherever it points, and a FIFO would
/// hang the export past the lock's deadline.
#[cfg(unix)]
#[tokio::test]
async fn a_link_or_fifo_at_the_export_lock_is_refused() {
    let m2 = tempdir().expect("m2");
    let lock = m2.path().join(".raeva-export.lock");
    let outside = tempdir().expect("outside");
    let target = outside.path().join("created");
    std::os::unix::fs::symlink(&target, &lock).unwrap();
    super::lock_destination(m2.path(), std::time::Duration::from_secs(1))
        .await
        .expect_err("refused");
    assert!(!target.exists());

    fs::remove_file(&lock).unwrap();
    let made = std::process::Command::new("mkfifo").arg(&lock).status();
    if !made.is_ok_and(|status| status.success()) {
        return;
    }
    tokio::time::timeout(
        std::time::Duration::from_secs(20),
        super::lock_destination(m2.path(), std::time::Duration::from_secs(1)),
    )
    .await
    .expect("no hang")
    .expect_err("refused");
}

/// A holder that keeps the export lock past the deadline fails the next
/// export instead of hanging it.
#[tokio::test]
async fn a_held_export_lock_times_out() {
    let m2 = tempdir().expect("m2");
    let wait = std::time::Duration::from_secs(5);
    let held = super::lock_destination(m2.path(), wait)
        .await
        .expect("free");
    let err = super::lock_destination(m2.path(), std::time::Duration::from_millis(100))
        .await
        .expect_err("held");
    assert!(
        matches!(&err, ExportError::IoError(io) if io.kind() == std::io::ErrorKind::TimedOut),
        "{err}"
    );
    assert!(err.to_string().contains(".raeva-export.lock"), "{err}");
    drop(held);
    super::lock_destination(m2.path(), wait)
        .await
        .expect("free after drop");
}

#[tokio::test]
async fn a_dry_run_refuses_populated_repository_ids_that_fold_to_one_path() {
    for snapshot in [false, true] {
        let mut f = Fixture::new();
        let mut row = jar("g", "a", if snapshot { "1-SNAPSHOT" } else { "1" });
        if snapshot {
            row.snapshot = SnapshotStamp::of_version("1-20240101.010101-1");
        }
        f.row(row, b"jar", b"pom").await;
        f.lock
            .repo_ids
            .insert(REPO.to_string(), ["Repo".into(), "repo".into()].into());
        let options = ExportOptions {
            dry_run: true,
            ..f.options()
        };
        let exporter = f.exporter(options);
        let result = if snapshot {
            exporter.export_items(&f.lock.platforms[0].artifacts).await
        } else {
            exporter.export(&Reactor::default()).await
        };
        let err =
            result.expect_err("an empty destination is assumed to fold case during a dry run");
        let relative = if snapshot {
            "g/a/1-SNAPSHOT/maven-metadata-repo.xml"
        } else {
            "g/a/maven-metadata-repo.xml"
        };
        assert!(
            matches!(&err.error, ExportError::CaseCollision { path, .. } if *path == f.m2().join(relative)),
            "{err}"
        );
        assert!(!f.m2().exists());
    }
}
