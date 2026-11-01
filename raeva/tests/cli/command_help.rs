use rv_test_support::{fixtures, golden};

use crate::common::{
    assert_status, assert_success, cli_command_dirs, cli_global_flags, raeva_command, temp_project,
};

#[test]
fn help_keeps_its_quick_start() {
    let (project, home) = temp_project();
    let mut command = raeva_command(project.path(), home.path());
    // Exercise Windows' argv[0] on Unix too.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.arg0("raeva.exe");
    }
    let output = command.arg("--help").output().expect("run raeva --help");
    assert_success(&output, "help");
    let help = String::from_utf8(output.stdout).expect("UTF-8 help");
    assert!(help.contains("Usage: raeva [OPTIONS] <COMMAND>"), "{help}");
    let quick = help
        .split("Quick start:")
        .nth(1)
        .and_then(|rest| rest.split("Usage:").next())
        .expect("quick start in help");
    let readme = fixtures::workspace_file("README.md");
    let mut commands = Vec::new();
    // The offline recipe is the README's, which keeps plugins apart.
    for section in ["## Quick start", "## Offline builds"] {
        let before = commands.len();
        for line in fixtures::markdown_fenced_lines(fixtures::markdown_section(&readme, section)) {
            let command = line.trim().split('#').next().unwrap_or("").trim();
            if !command.is_empty() {
                commands.push(command.to_string());
            }
        }
        assert!(
            commands.len() > before,
            "README {section} has no commands in a code fence"
        );
    }
    for command in commands {
        assert!(
            quick.contains(&command),
            "help quick start missing {command:?}: {quick}"
        );
    }
}

/// Commands `Session::require_network` names. A new call must fail
/// [`offline_is_global_and_refused_where_the_network_is_the_point`] until
/// `--offline` is refused there.
fn network_only_commands() -> Vec<String> {
    let mut names = Vec::new();
    for (rel, text) in fixtures::workspace_production_sources() {
        if !rel.starts_with("raeva/src/") {
            continue;
        }
        let text = fixtures::without_inline_test_module(&text);
        names.extend(fixtures::quoted_after(
            &text,
            concat!("require_network", "("),
        ));
    }
    names.sort();
    names.dedup();
    assert!(
        !names.is_empty(),
        "raeva/src must call Session::require_network"
    );
    names
}

/// `--offline` is global. Commands whose only job is a network call refuse
/// it as a usage error instead of failing on the first request.
#[test]
fn offline_is_global_and_refused_where_the_network_is_the_point() {
    let (project, home) = temp_project();
    for command in network_only_commands() {
        for args in [
            ["--offline", command.as_str()],
            [command.as_str(), "--offline"],
        ] {
            let output = raeva_command(project.path(), home.path())
                .args(args)
                .output()
                .expect("run raeva");
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert_status(&output, 2, &format!("{args:?}"));
            assert!(
                stderr.contains("cannot run with --offline"),
                "{args:?}: {stderr}"
            );
        }
    }

    let help = raeva_command(project.path(), home.path())
        .args(["tree", "--help"])
        .output()
        .expect("run raeva");
    assert_success(&help, "tree --help");
    assert!(
        String::from_utf8(help.stdout)
            .expect("UTF-8 help")
            .contains("--offline"),
        "global flag listed in every command's help"
    );
}

/// `COMPLETE` in the host shell must not turn `--help` into a completion
/// script. [`crate::common::raeva_command`] strips it from the child.
#[test]
fn complete_from_the_host_does_not_take_over_the_command() {
    let (project, home) = temp_project();
    temp_env::with_var("COMPLETE", Some("bash"), || {
        let output = raeva_command(project.path(), home.path())
            .arg("--help")
            .output()
            .expect("run raeva --help");
        assert_success(&output, "help with COMPLETE from the host");
        let help = String::from_utf8(output.stdout).expect("UTF-8 help");
        assert!(help.contains("Usage: raeva [OPTIONS] <COMMAND>"), "{help}");
    });
}

/// Adding a command must fail here until the README Commands table names it.
#[test]
fn the_readme_lists_every_command() {
    let readme = fixtures::workspace_file("README.md");
    let mut listed = Vec::new();
    for part in fixtures::markdown_first_column_parts(&readme, "## Commands") {
        let rest = part
            .strip_prefix("raeva ")
            .unwrap_or_else(|| panic!("Commands table cell must start with raeva: {part:?}"));
        let name = rest.split('<').next().expect("command").trim();
        listed.push(name.replace(' ', "-"));
    }
    listed.sort();
    assert_eq!(
        listed,
        cli_command_dirs(),
        "README Commands table and CLI commands differ"
    );
}

/// A new file under `docs/` must fail here until the README Documentation
/// list links it. A stray non-markdown file fails until it is listed too.
/// A `docs/` mention in prose or a code fence does not count. Images go in
/// `docs/assets/`.
#[test]
fn the_readme_links_every_doc() {
    let readme = fixtures::workspace_file("README.md");
    let mut mentioned = Vec::new();
    for (target, _) in
        fixtures::markdown_local_links(fixtures::markdown_section(&readme, "## Documentation"))
    {
        let Some(name) = target.strip_prefix("docs/") else {
            continue;
        };
        if name.ends_with(".md") && !name.contains('/') {
            mentioned.push(name.to_string());
        }
    }
    mentioned.sort();
    mentioned.dedup();
    let files: Vec<&str> = mentioned.iter().map(String::as_str).collect();
    fixtures::assert_children(
        &fixtures::workspace_root().join("docs"),
        &["assets"],
        &files,
    );
}

/// Adding a global option must fail here until the README Commands section
/// names it. `--help` and `--version` are clap's.
#[test]
fn the_readme_lists_every_global_flag() {
    let readme_text = fixtures::workspace_file("README.md");
    let readme = fixtures::markdown_section(&readme_text, "## Commands");
    let flags = cli_global_flags();
    assert!(!flags.is_empty(), "raeva --help must list global options");
    for (long, short) in flags {
        let named = readme.contains(&format!("--{long}"))
            || short.is_some_and(|flag| readme.contains(&format!("-{flag}")));
        assert!(named, "README Commands section must name --{long}");
    }
}

/// User-facing Markdown: `*.md` at the workspace root, everything under
/// `docs/`, and every `README.md` or `CHANGELOG.md` elsewhere. A new crate
/// or fixture README is included; `plans/`, `target/`, and dot-directories
/// are not.
fn user_markdown_files() -> Vec<String> {
    let root = fixtures::workspace_root();
    let mut files = Vec::new();
    collect_user_markdown(&root, "", &mut files);
    files.sort();
    files.dedup();
    files
}

fn collect_user_markdown(dir: &std::path::Path, rel: &str, files: &mut Vec<String>) {
    for name in fixtures::sorted_child_names(dir, |_| true) {
        if name.starts_with('.') || name == "target" || name == "plans" {
            continue;
        }
        let path = dir.join(&name);
        let child = if rel.is_empty() {
            name.clone()
        } else {
            format!("{rel}/{name}")
        };
        if path.is_dir() {
            collect_user_markdown(&path, &child, files);
        } else if keep_user_markdown(rel, &name) {
            files.push(child);
        }
    }
}

fn keep_user_markdown(parent: &str, name: &str) -> bool {
    name.ends_with(".md")
        && (parent.is_empty()
            || parent == "docs"
            || parent.starts_with("docs/")
            || name == "README.md"
            || name == "CHANGELOG.md")
}

/// A relative Markdown link in the user-facing docs must name a file that
/// exists, and a `#fragment` must be a heading slug in that file. A same-file
/// `#anchor` is included; a `docs/` file the README does not list still fails
/// [`the_readme_links_every_doc`].
#[test]
fn every_doc_relative_link_resolves() {
    let root = fixtures::workspace_root();
    for rel in user_markdown_files() {
        let text = fixtures::workspace_file(&rel);
        let dir = root.join(&rel).parent().expect("parent").to_path_buf();
        for (target, fragment) in fixtures::markdown_local_links(&text) {
            let file = if target.is_empty() {
                root.join(&rel)
            } else {
                dir.join(&target)
            };
            let shown = if target.is_empty() {
                format!("#{fragment}", fragment = fragment.as_deref().unwrap_or(""))
            } else if let Some(fragment) = &fragment {
                format!("{target}#{fragment}")
            } else {
                target.clone()
            };
            assert!(file.is_file(), "{rel} links to {shown}, which is missing");
            let Some(fragment) = fragment else {
                continue;
            };
            if file.extension().is_none_or(|ext| ext != "md") {
                continue;
            }
            let dest = if target.is_empty() {
                text.clone()
            } else {
                std::fs::read_to_string(&file).expect("read linked markdown")
            };
            let slugs = fixtures::markdown_heading_slugs(&dest);
            assert!(
                slugs.iter().any(|slug| slug == &fragment),
                "{rel} links to {shown}, which is not a heading"
            );
        }
    }
}

/// Workspace members are the directories with a `Cargo.toml`. A published
/// crate must ship a README and both license files; `publish = false` does
/// not.
#[test]
fn every_workspace_crate_is_accounted_for() {
    let root = fixtures::workspace_root();
    let cargo: toml::Value =
        toml::from_str(&fixtures::workspace_file("Cargo.toml")).expect("workspace Cargo.toml");
    let mut members: Vec<String> = cargo["workspace"]["members"]
        .as_array()
        .expect("workspace.members")
        .iter()
        .map(|member| member.as_str().expect("member path").to_string())
        .collect();
    members.sort();
    let found = fixtures::sorted_child_names(&root, |path| {
        path.is_dir() && path.join("Cargo.toml").is_file()
    });
    assert_eq!(
        found, members,
        "workspace members and crate directories differ"
    );
    for name in &members {
        let dir = root.join(name);
        let manifest: toml::Value = toml::from_str(
            &std::fs::read_to_string(dir.join("Cargo.toml")).expect("crate Cargo.toml"),
        )
        .expect("parse crate Cargo.toml");
        let publish = manifest
            .get("package")
            .and_then(|package| package.get("publish"))
            .and_then(toml::Value::as_bool)
            .unwrap_or(true);
        if !publish {
            continue;
        }
        for file in ["README.md", "LICENSE-APACHE", "LICENSE-MIT"] {
            assert!(
                dir.join(file).is_file(),
                "{name} is published and missing {file}"
            );
        }
    }
}

/// A new file or directory under `dir` must fail here until `source`
/// declares it. Directory modules are checked the same way via their
/// `mod.rs`, so a stray file in `common/` or `schemas/` fails too.
fn assert_test_modules(dir: &std::path::Path, source: &str) {
    let modules = fixtures::rust_mod_declarations(source);
    let dirs = fixtures::sorted_child_names(dir, |path| path.is_dir());
    let rs =
        fixtures::sorted_child_names(dir, |path| path.extension().is_some_and(|ext| ext == "rs"));
    let mut found: Vec<String> = dirs
        .iter()
        .cloned()
        .chain(
            rs.iter()
                .filter(|name| *name != "main.rs" && *name != "mod.rs")
                .map(|name| name.trim_end_matches(".rs").to_string()),
        )
        .collect();
    found.sort();
    assert_eq!(
        found,
        modules,
        "{} files and module declarations differ",
        dir.display()
    );
    let files: Vec<&str> = rs.iter().map(String::as_str).collect();
    let dir_names: Vec<&str> = dirs.iter().map(String::as_str).collect();
    fixtures::assert_children(dir, &dir_names, &files);
    for name in dirs {
        let child = dir.join(&name);
        let text = std::fs::read_to_string(child.join("mod.rs"))
            .unwrap_or_else(|error| panic!("read {name}/mod.rs: {error}"));
        assert_test_modules(&child, &text);
    }
}

/// A new `tests/cli/*.rs` file or directory must fail here until `main.rs`
/// declares it. A stray file at this level, or inside a directory module,
/// fails until it is listed.
#[test]
fn every_cli_test_file_is_a_module() {
    let root = fixtures::workspace_root().join("raeva/tests/cli");
    assert_test_modules(&root, include_str!("main.rs"));
}

/// `raeva/tests/` holds the CLI integration binary and its vendored schemas.
/// A new directory or a stray file at either level must fail here.
#[test]
fn every_raeva_test_directory_is_accounted_for() {
    let tests = fixtures::workspace_root().join("raeva/tests");
    fixtures::assert_children(&tests, &["cli", "fixtures"], &[]);
    fixtures::assert_children(&tests.join("fixtures"), &["schemas"], &[]);
}

/// docs/configuration.md names every `raeva.toml` / `config.toml` key the
/// `Deserialize` structs in config.rs and settings.rs accept, including
/// `rename` names. Table names may appear as `[[key]]` or `[key]`. A new
/// struct or field must fail here until that section mentions it.
#[test]
fn the_docs_name_every_config_toml_key() {
    let mut keys = Vec::new();
    for (rel, text) in fixtures::workspace_production_sources() {
        // Maven option parsing also owns JSON lookup recipes stored in the lock.
        if !rel.starts_with("rv-config/src/") || rel == "rv-config/src/maven_config.rs" {
            continue;
        }
        let source = fixtures::without_inline_test_module(&text);
        if !source.contains("deny_unknown_fields") {
            continue;
        }
        let names = fixtures::serde_deserialize_structs(&source);
        assert!(
            !names.is_empty(),
            "{rel} has deny_unknown_fields but no Deserialize struct"
        );
        for name in names {
            keys.extend(fixtures::serde_struct_fields(&source, &name));
        }
    }
    keys.sort();
    keys.dedup();
    assert!(
        !keys.is_empty(),
        "rv-config must declare a Deserialize struct with deny_unknown_fields"
    );
    let docs = fixtures::workspace_file("docs/configuration.md");
    let section = fixtures::markdown_section(&docs, "## `raeva.toml` and `config.toml`");
    fixtures::assert_markdown_names(section, "docs/configuration.md toml section", &keys);
}

/// Environment variables production code reads must appear in the
/// configuration environment table. Test-only names and Cargo's are omitted.
#[test]
fn the_docs_name_every_env_var_the_code_reads() {
    let docs = fixtures::workspace_file("docs/configuration.md");
    let named = fixtures::markdown_first_column_parts(&docs, "## Environment variables");
    let mut found = Vec::new();
    for (_, text) in fixtures::workspace_production_sources() {
        let text = fixtures::without_inline_test_module(&text);
        found.extend(fixtures::quoted_after(&text, concat!("_ENV", ": &str = ")));
        found.extend(fixtures::quoted_after(&text, concat!("env::var_os", "(")));
        found.extend(fixtures::quoted_after(&text, concat!("env::var", "(")));
    }
    found.retain(|name| !name.is_empty() && !name.starts_with("CARGO_") && !name.contains("TEST"));
    found.sort();
    found.dedup();
    assert!(!found.is_empty(), "production code must read an env var");
    for name in found {
        assert!(
            named.iter().any(|listed| listed == &name),
            "docs/configuration.md environment table must name {name}"
        );
    }
}

/// The help of the commands people read first, compared with the files under
/// `test-fixtures/help/`. Regenerate with `RAEVA_TEST_BLESS=1 cargo test -p
/// raeva --test cli -- help_matches` and review the diff.
#[test]
fn help_matches_the_snapshots() {
    let (project, home) = temp_project();
    for (name, args) in [
        ("raeva", &["--help"][..]),
        ("sync", &["sync", "--help"]),
        ("lock-diff", &["lock", "diff", "--help"]),
        ("sbom", &["sbom", "--help"]),
        ("vuln", &["vuln", "--help"]),
        ("vuln-triage", &["vuln", "triage", "--help"]),
    ] {
        let output = raeva_command(project.path(), home.path())
            .args(args)
            .output()
            .expect("run raeva --help");
        assert_success(&output, name);
        let help = String::from_utf8(output.stdout).expect("UTF-8 help");
        golden::assert_golden(&fixtures::path("help").join(format!("{name}.txt")), &help);
    }
}
