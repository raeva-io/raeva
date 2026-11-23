use std::collections::BTreeMap;

use rv_maven_types::MavenMode::{self, Maven39, Maven310};

use super::*;

const GROUP_ON: (&str, &str) = ("aether.remoteRepositoryFilter.groupId", "true");
const PREFIXES_ON: (&str, &str) = ("aether.remoteRepositoryFilter.prefixes", "true");

fn filters(
    mode: MavenMode,
    properties: &[(&str, &str)],
    files: &[(&str, &str, &[u8])],
) -> RepositoryFilters {
    RepositoryFilters::from_files(mode, properties, files).expect("filters load")
}

fn allows(filters: &RepositoryFilters, id: &str, group: &str) -> bool {
    let path = format!("{}/x/1/x-1.jar", group.replace('.', "/"));
    filters
        .rejects(Some(id), "https://r.example/", group, &path)
        .is_none()
}

fn allows_path(filters: &RepositoryFilters, id: &str, path: &str) -> bool {
    filters
        .rejects(Some(id), "https://r.example/", "g", path)
        .is_none()
}

#[test]
fn maven_39_matches_a_group_id_exactly_and_maven_310_matches_the_groups_below() {
    let files: &[(&str, &str, &[u8])] =
        &[("groupId", "groupId-r1.txt", b"# comment\norg.ex.b\n\n")];
    let v39 = filters(Maven39, &[GROUP_ON], files);
    assert!(allows(&v39, "r1", "org.ex.b"));
    assert!(!allows(&v39, "r1", "org.ex.b.sub"));
    assert!(!allows(&v39, "r1", "org.ex.a"));
    assert!(
        allows(&v39, "r2", "org.ex.a"),
        "a repository without a file takes all"
    );
    let v310 = filters(Maven310, &[GROUP_ON], files);
    assert!(allows(&v310, "r1", "org.ex.b"));
    assert!(allows(&v310, "r1", "org.ex.b.sub"));
    assert!(!allows(&v310, "r1", "org.ex.a"));
    assert!(!allows(&v310, "r1", "org.ex"));
}

#[test]
fn a_maven_39_group_id_rule_is_the_line_as_written() {
    let files: &[(&str, &str, &[u8])] =
        &[("groupId", "groupId-r1.txt", b"org.ex.b \r\norg.ex.c\r\n")];
    let v39 = filters(Maven39, &[GROUP_ON], files);
    assert!(!allows(&v39, "r1", "org.ex.b"));
    assert!(allows(&v39, "r1", "org.ex.c"));
}

#[test]
fn maven_310_group_rules_follow_their_modifiers_and_the_last_rule_wins() {
    let rules =
        b"org.apache.maven\n!=org.apache.maven.foo\n!org.apache.maven.indexer\n=org.apache.bar\n";
    let files: &[(&str, &str, &[u8])] = &[("groupId", "groupId-r1.txt", rules)];
    let v310 = filters(Maven310, &[GROUP_ON], files);
    for (group, allowed) in [
        ("org.apache.maven", true),
        ("org.apache.maven.plugins", true),
        ("org.apache.maven.foo", false),
        ("org.apache.maven.foo.bar", true),
        ("org.apache.maven.indexer", false),
        ("org.apache.maven.indexer.x", false),
        ("org.apache.bar", true),
        ("org.apache.bar.baz", false),
        ("org.apache", false),
    ] {
        assert_eq!(allows(&v310, "r1", group), allowed, "{group}");
    }
    let open: &[(&str, &str, &[u8])] = &[(
        "groupId",
        "groupId-r1.txt",
        b"*\n!org.bad\norg.bad\n!org.worse\n",
    )];
    let v310 = filters(Maven310, &[GROUP_ON], open);
    assert!(allows(&v310, "r1", "com.any"));
    assert!(allows(&v310, "r1", "org.bad.x"));
    assert!(!allows(&v310, "r1", "org.worse"));
}

#[test]
fn a_maven_310_group_rule_that_names_no_group_fails_the_load() {
    let files: &[(&str, &str, &[u8])] = &[("groupId", "groupId-r1.txt", b"!\n")];
    let error = RepositoryFilters::from_files(Maven310, &[GROUP_ON], files).unwrap_err();
    assert!(error.to_string().contains("names no groupId"), "{error}");
}

#[test]
fn a_prefix_admits_the_paths_below_its_deepest_entries() {
    let files: &[(&str, &str, &[u8])] = &[(
        "prefixes",
        "prefixes-r1.txt",
        b"## repository-prefixes/2.0\n/org/ex/b/sub\n/org/ex/b\n/com/x\n",
    )];
    for mode in [Maven39, Maven310] {
        let f = filters(mode, &[PREFIXES_ON], files);
        assert!(
            allows_path(&f, "r1", "org/ex/b/sub/c1/1.0/c1-1.0.pom"),
            "{mode:?}"
        );
        assert!(
            !allows_path(&f, "r1", "org/ex/b/b1/1.0/b1-1.0.pom"),
            "{mode:?}"
        );
        assert!(
            allows_path(&f, "r1", "com/x/y/maven-metadata.xml"),
            "{mode:?}"
        );
        assert!(!allows_path(&f, "r1", "com/maven-metadata.xml"), "{mode:?}");
        assert!(allows_path(&f, "r2", "net/y/1/y-1.jar"), "{mode:?}");
    }
}

#[test]
fn a_prefixes_file_without_entries_admits_nothing() {
    let files: &[(&str, &str, &[u8])] = &[(
        "prefixes",
        "prefixes-r1.txt",
        b"## repository-prefixes/2.0\n",
    )];
    for mode in [Maven39, Maven310] {
        let f = filters(mode, &[PREFIXES_ON], files);
        assert!(
            !allows_path(&f, "r1", "org/ex/b/b1/1.0/b1-1.0.pom"),
            "{mode:?}"
        );
    }
}

#[test]
fn maven_310_ignores_a_prefixes_file_without_its_header() {
    let files: &[(&str, &str, &[u8])] = &[("prefixes", "prefixes-r1.txt", b"/org/ex/b\n")];
    let v39 = filters(Maven39, &[PREFIXES_ON], files);
    assert!(!allows_path(&v39, "r1", "org/ex/a/a1/1.0/a1-1.0.pom"));
    let v310 = filters(Maven310, &[PREFIXES_ON], files);
    assert!(allows_path(&v310, "r1", "org/ex/a/a1/1.0/a1-1.0.pom"));
    let rejected = |bad: &[u8]| {
        let files: &[(&str, &str, &[u8])] = &[("prefixes", "prefixes-r1.txt", bad)];
        filters(Maven310, &[PREFIXES_ON], files)
    };
    for bad in [
        &b"## repository-prefixes/2.0\n/org:x\n"[..],
        b"## repository-prefixes/2.0\n@ unsupported\n",
        b"",
        b"\xff",
    ] {
        assert!(
            allows_path(&rejected(bad), "r1", "org/ex/a/a1/1.0/a1-1.0.pom"),
            "{bad:?}"
        );
        // An ignored file's bytes do not change what the build requests.
        assert_eq!(
            rejected(bad).rule_input(|_| false),
            rejected(b"/org/ex/b\n").rule_input(|_| false),
            "{bad:?}"
        );
    }
}

#[test]
fn maven_39_filters_only_when_enabled_and_maven_310_unless_disabled() {
    let files: &[(&str, &str, &[u8])] = &[
        ("groupId", "groupId-r1.txt", b"org.ex.b\n"),
        (
            "prefixes",
            "prefixes-r1.txt",
            b"## repository-prefixes/2.0\n/org/ex/b\n",
        ),
    ];
    assert!(!filters(Maven39, &[], files).is_active());
    let v310 = filters(Maven310, &[], files);
    assert!(!allows(&v310, "r1", "org.ex.a"));
    for off in [
        &[
            ("aether.remoteRepositoryFilter.groupId", "false"),
            ("aether.remoteRepositoryFilter.prefixes", "FALSE"),
        ][..],
        &[
            ("aether.remoteRepositoryFilter.groupId.skipped", "true"),
            ("aether.remoteRepositoryFilter.prefixes.skipped", "true"),
        ],
        &[
            ("aether.remoteRepositoryFilter.groupId.r1", "false"),
            ("aether.remoteRepositoryFilter.prefixes.*", "false"),
        ],
        &[
            ("aether.remoteRepositoryFilter.groupId.skipped.*", "true"),
            ("aether.remoteRepositoryFilter.prefixes.skipped.r1", "true"),
        ],
    ] {
        assert!(
            allows(&filters(Maven310, off, files), "r1", "org.ex.a"),
            "{off:?}"
        );
    }
    let recording = [
        GROUP_ON,
        ("aether.remoteRepositoryFilter.groupId.record", "true"),
    ];
    assert!(!filters(Maven39, &recording, files).is_active());
    // Only `true`, in any case, enables a filter.
    assert!(
        !filters(
            Maven39,
            &[("aether.remoteRepositoryFilter.groupId", "yes")],
            files
        )
        .is_active()
    );
    assert!(
        filters(
            Maven39,
            &[("aether.remoteRepositoryFilter.groupId", "TRUE")],
            files
        )
        .is_active()
    );
}

#[test]
fn maven_310_turns_away_a_repository_without_rules_when_no_input_outcome_is_false() {
    let files: &[(&str, &str, &[u8])] = &[("groupId", "groupId-r1.txt", b"org.ex.b\n")];
    let strict = filters(
        Maven310,
        &[(
            "aether.remoteRepositoryFilter.groupId.noInputOutcome",
            "false",
        )],
        files,
    );
    assert!(!allows(&strict, "r2", "org.ex.a"));
    let one = filters(
        Maven310,
        &[
            (
                "aether.remoteRepositoryFilter.groupId.noInputOutcome",
                "false",
            ),
            (
                "aether.remoteRepositoryFilter.groupId.noInputOutcome.r2",
                "true",
            ),
        ],
        files,
    );
    assert!(allows(&one, "r2", "org.ex.a"));
    assert!(!allows(&one, "r3", "org.ex.a"));
    let v39 = filters(
        Maven39,
        &[
            GROUP_ON,
            (
                "aether.remoteRepositoryFilter.groupId.noInputOutcome",
                "false",
            ),
        ],
        files,
    );
    assert!(allows(&v39, "r2", "org.ex.a"));
}

#[test]
fn maven_310_looks_for_the_id_and_url_key_before_the_id() {
    let url = "https://r.example/";
    let keyed = format!(
        "groupId-r1-{}.txt",
        Sha1::from_bytes(url.as_bytes()).as_str()
    );
    let files: &[(&str, &str, &[u8])] = &[
        ("groupId", &keyed, b"org.ex.a\n"),
        ("groupId", "groupId-r1.txt", b"org.ex.b\n"),
    ];
    let v310 = filters(Maven310, &[], files);
    assert!(allows(&v310, "r1", "org.ex.a"));
    assert!(!allows(&v310, "r1", "org.ex.b"));
    let v39 = filters(Maven39, &[GROUP_ON], files);
    assert!(allows(&v39, "r1", "org.ex.b"));
    let odd = filters(
        Maven310,
        &[],
        &[("groupId", "groupId-a-SLASH-b.txt", b"org.ex.b\n")],
    );
    assert!(!allows(&odd, "a/b", "org.ex.a"));
}

#[test]
fn both_filters_must_admit_a_request() {
    let files: &[(&str, &str, &[u8])] = &[
        ("groupId", "groupId-r1.txt", b"org.ex.b\n"),
        (
            "prefixes",
            "prefixes-r1.txt",
            b"## repository-prefixes/2.0\n/org/ex/b/sub\n",
        ),
    ];
    let v39 = filters(Maven39, &[GROUP_ON, PREFIXES_ON], files);
    assert!(
        v39.rejects(Some("r1"), "u", "org.ex.b", "org/ex/b/b1/1/b1-1.pom")
            .is_some()
    );
    assert!(
        v39.rejects(
            Some("r1"),
            "u",
            "org.ex.b.sub",
            "org/ex/b/sub/c1/1/c1-1.pom"
        )
        .is_some()
    );
    let v310 = filters(Maven310, &[], files);
    assert!(
        v310.rejects(
            Some("r1"),
            "u",
            "org.ex.b.sub",
            "org/ex/b/sub/c1/1/c1-1.pom"
        )
        .is_none()
    );
    assert!(
        v310.rejects(Some("r1"), "u", "org.ex.b", "org/ex/b/b1/1/b1-1.pom")
            .is_some()
    );
}

#[test]
fn the_graph_inputs_are_the_settings_and_rule_files_but_not_the_basedir() {
    let all = |_: &str| false;
    let none = |_: &str| true;
    assert_eq!(filters(Maven39, &[], &[]).rule_input(all), None);
    assert_eq!(filters(Maven310, &[], &[]).rule_input(all), None);
    let base = [
        GROUP_ON,
        ("aether.remoteRepositoryFilter.groupId.basedir", "/a"),
    ];
    let one = filters(
        Maven39,
        &base,
        &[("groupId", "groupId-r1.txt", b"org.ex.b\n")],
    );
    assert_eq!(
        one.property_names().collect::<Vec<_>>(),
        ["aether.remoteRepositoryFilter.groupId"]
    );
    let moved = [
        GROUP_ON,
        ("aether.remoteRepositoryFilter.groupId.basedir", "/b"),
    ];
    let same = filters(
        Maven39,
        &moved,
        &[("groupId", "groupId-r1.txt", b"org.ex.b\n")],
    );
    assert_eq!(one.rule_input(all), same.rule_input(all));
    let edited = filters(
        Maven39,
        &base,
        &[("groupId", "groupId-r1.txt", b"org.ex.c\n")],
    );
    assert_ne!(one.rule_input(none), edited.rule_input(none));
    let input = one.rule_input(all).unwrap();
    assert!(
        input.contains("property aether.remoteRepositoryFilter.groupId=true"),
        "{input}"
    );
    assert!(input.contains("file groupId-r1.txt "), "{input}");
    assert!(!input.contains("basedir"), "{input}");
    let listed = one.rule_input(none).unwrap();
    assert!(!listed.contains("property"), "{listed}");
}

#[test]
fn rule_files_are_read_from_the_basedir_or_the_local_repository() {
    let root = tempfile::tempdir().unwrap();
    let local = root.path().join("m2");
    std::fs::create_dir_all(local.join(".remoteRepositoryFilters")).unwrap();
    std::fs::write(
        local.join(".remoteRepositoryFilters/groupId-r1.txt"),
        "org.ex.b\n",
    )
    .unwrap();
    std::fs::write(
        local.join(".remoteRepositoryFilters/other-r1.txt"),
        "org.ex.a\n",
    )
    .unwrap();
    std::fs::create_dir_all(local.join("rel")).unwrap();
    std::fs::write(local.join("rel/groupId-r1.txt"), "org.ex.c\n").unwrap();
    let project = root.path().join("p/.mvn/rrf");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(project.join("groupId-r1.txt"), "org.ex.d\n").unwrap();
    let props = |extra: &[(&str, &str)]| -> BTreeMap<String, String> {
        [GROUP_ON, ("unrelated", "x")]
            .iter()
            .chain(extra)
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    };
    let load =
        |extra: &[(&str, &str)]| RepositoryFilters::load(Maven39, props(extra), &local).unwrap();
    assert!(allows(&load(&[]), "r1", "org.ex.b"));
    assert!(!allows(&load(&[]), "r1", "org.ex.a"));
    let rel = load(&[("aether.remoteRepositoryFilter.groupId.basedir", "rel")]);
    assert!(allows(&rel, "r1", "org.ex.c"));
    let dir = format!("{}/./x/../", project.display());
    let abs = load(&[("aether.remoteRepositoryFilter.groupId.basedir", &dir)]);
    assert!(allows(&abs, "r1", "org.ex.d") && !allows(&abs, "r1", "org.ex.b"));
    assert!(!abs.property_names().any(|name| name == "unrelated"));
    let missing = load(&[("aether.remoteRepositoryFilter.groupId.basedir", "nowhere")]);
    assert!(allows(&missing, "r1", "org.ex.a"));
    let file = project.join("groupId-r1.txt").display().to_string();
    let error = RepositoryFilters::load(
        Maven39,
        props(&[("aether.remoteRepositoryFilter.groupId.basedir", &file)]),
        &local,
    )
    .unwrap_err();
    assert!(error.to_string().contains("not a directory"), "{error}");
}

#[test]
fn a_group_id_file_that_is_not_utf8_fails_the_load() {
    let files: &[(&str, &str, &[u8])] = &[("groupId", "groupId-r1.txt", b"org.\xff\n")];
    for mode in [Maven39, Maven310] {
        let error = RepositoryFilters::from_files(mode, &[GROUP_ON], files).unwrap_err();
        assert!(
            matches!(error, ConfigError::ProjectInputEncoding { .. }),
            "{error}"
        );
    }
}
