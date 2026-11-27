//! How the project fits raeva, from local files only: these checks run
//! before any repository is asked, and under `--offline`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use rv_config::Config;
use rv_lock::Platform;

use super::{Outcome, Row};
use crate::output::WarningCode;

/// Where the pages doctor points to are, for a binary install too.
const DOCS: &str = "https://github.com/raeva-io/raeva/blob/main/docs/";

/// The POM file names of Maven Polyglot, besides `pom.xml`. A `Gemfile`
/// or a `.gemspec`, which Polyglot Ruby also reads, is left out: alone it
/// is an ordinary Ruby project.
const POLYGLOT_POMS: &[&str] = &[
    "pom.yaml",
    "pom.yml",
    "pom.kts",
    "pom.groovy",
    "pom.gy",
    "pom.rb",
    "Mavenfile",
    "Jarfile",
    "pom.scala",
    "pom.clj",
    "pom.atom",
    "pom.java",
];

/// The `groupId` of the Maven Polyglot core extensions.
const POLYGLOT_GROUP: &str = "io.takari.polyglot";

/// os-maven-plugin, whose `os.detected.*` properties raeva sets itself.
const OS_MAVEN_PLUGIN: &str = "kr.motd.maven:os-maven-plugin";

/// CI configuration files, relative to the git root, or directories whose
/// YAML files are such files.
const CI_FILES: &[&str] = &[
    ".gitlab-ci.yml",
    "Jenkinsfile",
    "azure-pipelines.yml",
    "bitbucket-pipelines.yml",
    ".travis.yml",
    ".circleci/config.yml",
];
const CI_DIRS: &[&str] = &[".github/workflows", ".buildkite", ".woodpecker"];

/// The `.gitattributes` line docs/ci.md gives.
const GITATTRIBUTES_LINE: &str = "raeva.lock linguist-generated=true";

/// raeva.lock as a sync reads it, when it is a file.
type LockRead = crate::error::Result<rv_lock::Lockfile>;

/// Text to put into a file, which doctor prints and never writes.
pub(super) struct Snippet {
    pub(super) file: &'static str,
    pub(super) text: String,
}

#[derive(Default)]
pub(super) struct Preflight {
    pub(super) rows: Vec<Row>,
    pub(super) snippets: Vec<Snippet>,
}

/// The project checks for the project at `config.project_root`, none
/// outside a Maven project. `offline` makes a reactor that cannot be read
/// a failure, which the repository probes report otherwise.
pub(super) fn check(config: &Config, offline: bool) -> Preflight {
    let root = &config.project_root;
    let mut found = Preflight::default();
    let pom = root.join("pom.xml").is_file();
    let polyglot: Vec<&str> = (POLYGLOT_POMS.iter().copied())
        .filter(|name| root.join(name).is_file())
        .collect();
    if !pom && polyglot.is_empty() {
        return found;
    }
    found.rows.push(maven_mode_row(config));
    found.rows.extend(central_row(config));
    let mvn = config.mvn_dir();
    let core = core_extensions(&mvn);
    if let Some(row) = polyglot_row(pom, &polyglot, &core) {
        found.rows.push(row);
    }
    if pom {
        found.rows.extend(extensions_row(config, &core, offline));
    }
    found.rows.extend(maven_config_row(&mvn));
    let lock = match crate::commands::util::read_lockfile_at(&config.lock_path) {
        Err(crate::error::CliError::LockfileMissing { .. }) => None,
        read => Some(read),
    };
    let mut plugins = plugins_row(config.plugins.is_some(), lock.as_ref());
    if let Some(Err(err)) = (config.plugin_trace()).map(|trace| trace.launcher(root)) {
        plugins = Row::new("plugins", err.to_string(), Outcome::Config);
    } else if plugins.outcome == Outcome::Ok
        && let Some(Ok(lock)) = &lock
        && let Some(row) = trace_row(config, lock)
    {
        plugins = row;
    }
    found.rows.push(plugins);
    found
        .rows
        .extend(lock.as_ref().map(|lock| platforms_row(lock, config)));
    if let Some(git_root) = git_root(root) {
        ci_check(root, &git_root, &mut found);
        gitattributes_check(root, &git_root, &mut found);
    }
    found
}

/// Whether raeva.lock pins the build's plugins, as `wanted`, which
/// `[plugins] lock` in raeva.toml sets, asks.
fn plugins_row(wanted: bool, lock: Option<&LockRead>) -> Row {
    const CHECK: &str = "plugins";
    let platforms = lock
        .and_then(|lock| lock.as_ref().ok())
        .map(|lock| &lock.platforms);
    let held = |entry: &rv_lock::LockPlatform| entry.plugins.is_some();
    let stale = |what: &str| {
        let details = format!("{what}, so raeva sync --frozen fails; run raeva sync");
        Row::new(CHECK, details, Outcome::Warn).with_code(WarningCode::PluginTablesStale)
    };
    match platforms {
        None if lock.is_some() => Row::new(
            CHECK,
            "not checked, since raeva.lock cannot be read",
            Outcome::Info,
        ),
        Some(platforms) if wanted && !platforms.is_empty() && platforms.iter().all(held) => {
            Row::new(
                CHECK,
                "raeva.lock pins the build's plugins and extensions",
                Outcome::Ok,
            )
        }
        Some(platforms) if wanted => {
            let lacking: Vec<String> = (platforms.iter())
                .filter(|entry| !held(entry))
                .map(|entry| entry.platform.to_string())
                .collect();
            let lacking = match lacking.is_empty() {
                true => String::new(),
                false => format!(" for {}", lacking.join(", ")),
            };
            stale(&format!(
                "raeva.toml sets [plugins] lock = true, but raeva.lock lacks plugin tables{lacking}"
            ))
        }
        None if wanted => Row::new(
            CHECK,
            "raeva.toml sets [plugins] lock = true, so raeva sync locks the build's plugins \
             and extensions",
            Outcome::Info,
        ),
        Some(platforms) if platforms.iter().any(held) => stale(
            "raeva.lock holds plugin tables, which raeva.toml does not ask for with [plugins] \
             lock = true",
        ),
        _ => {
            let details = format!(
                "raeva.lock holds no plugin tables, so it pins no Maven plugins, and build \
                 extensions only for a module that resolves a dependency type Maven's core \
                 does not define: \
                 '[plugins] lock = true' in raeva.toml locks the plugins and build extensions, \
                 and '[plugins] trace' the artifacts they fetch while they run \
                 ({DOCS}offline-builds.md)"
            );
            Row::new(CHECK, details, Outcome::Info).with_code(WarningCode::PluginsNotLocked)
        }
    }
}

/// A warning when `raeva sync --frozen` refuses `lock`'s plugin tables
/// without resolving, as it does tables from other inputs or a trace of
/// another build, or, with `[plugins] trace`, an OS and architecture with
/// no trace of that build: this machine's first, then the others.
fn trace_row(config: &Config, lock: &rv_lock::Lockfile) -> Option<Row> {
    let stale = |details: String| {
        Row::new("plugins", details, Outcome::Warn).with_code(WarningCode::PluginTablesStale)
    };
    let platforms: Vec<Platform> = (lock.platforms.iter())
        .map(|entry| entry.platform.clone())
        .collect();
    if let Err(err) = crate::commands::sync::check_plugin_tables(config, Some(lock), &platforms) {
        let details = match err {
            crate::error::CliError::LockfileMismatch { details, .. } => details,
            err => err.to_string(),
        };
        return Some(stale(format!(
            "{details}, so raeva sync --frozen fails; run raeva sync"
        )));
    }
    config.plugin_trace()?;
    let host = Platform::current().ok()?.os_arch();
    let systems: BTreeSet<String> = (lock.platforms.iter())
        .map(|entry| entry.platform.os_arch())
        .collect();
    let untraced =
        |os_arch: &&String| !crate::commands::sync::traced_on(config, &lock.platforms, os_arch);
    if systems.get(&host).filter(untraced).is_some() {
        return Some(stale(format!(
            "raeva.toml's [plugins] trace or mvn has no matching trace in raeva.lock for \
             {host}, so raeva sync --frozen fails; run raeva sync online"
        )));
    }
    let others: Vec<&str> = (systems.iter())
        .filter(|os_arch| **os_arch != host)
        .filter(untraced)
        .map(String::as_str)
        .collect();
    (!others.is_empty()).then(|| {
        stale(format!(
            "raeva.lock has no trace for {} of the build [plugins] trace names, so raeva sync \
             --frozen there fails until an online raeva sync runs on that OS",
            others.join(", ")
        ))
    })
}

/// The Maven line resolution follows and what selected it.
fn maven_mode_row(config: &Config) -> Row {
    const CHECK: &str = "Maven mode";
    let selection = &config.lock.maven;
    let source = match &selection.source {
        rv_config::MavenModeSource::Default => {
            "neither [lock] maven nor a Maven wrapper names one".to_string()
        }
        source => format!("from {source}"),
    };
    Row::new(
        CHECK,
        format!("Maven {}, {source}", selection.mode),
        Outcome::Info,
    )
}

/// The URL that replaces Maven Central's in the Maven 3.10 mode, and where
/// it was set.
fn central_row(config: &Config) -> Option<Row> {
    let (url, origin) = config.replaced_central()?;
    Some(Row::new(
        "Maven Central",
        format!(
            "replaced by {} from {origin}, as Maven 3.10 replaces it",
            rv_config::redact_url(url)
        ),
        Outcome::Info,
    ))
}

/// The core extensions `.mvn/extensions.xml` loads, as `groupId:artifactId`,
/// or why the file cannot be read; `mvn` is the launcher's `.mvn`.
fn core_extensions(mvn: &Path) -> Result<Vec<String>, String> {
    let path = mvn.join("extensions.xml");
    let text = match rv_config::read_optional_project_input_string(&path) {
        Ok(Some(text)) => text,
        Ok(None) => return Ok(Vec::new()),
        Err(err) => return Err(err.to_string()),
    };
    let extensions = rv_maven_model::parse_core_extensions(&text).map_err(|err| err.to_string())?;
    Ok((extensions.iter())
        .map(|extension| format!("{}:{}", extension.group_id, extension.artifact_id))
        .collect())
}

/// Maven Polyglot: a core extension of its group, or a polyglot POM where
/// no `pom.xml` is.
fn polyglot_row(pom: bool, polyglot: &[&str], core: &Result<Vec<String>, String>) -> Option<Row> {
    let extensions: Vec<&String> = (core.iter().flatten())
        .filter(|key| key.starts_with(&format!("{POLYGLOT_GROUP}:")))
        .collect();
    let found = match (pom, extensions.is_empty()) {
        (false, _) => format!("{} and no pom.xml", polyglot.join(", ")),
        (true, false) => format!(
            "{} in .mvn/extensions.xml",
            extensions
                .iter()
                .map(|key| key.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
        (true, true) => return None,
    };
    Some(
        Row::new(
            "polyglot Maven",
            format!(
                "{found}: raeva reads pom.xml files only, so it cannot lock a project whose \
                 POMs Maven Polyglot reads"
            ),
            Outcome::Warn,
        )
        .with_code(WarningCode::PolyglotMaven),
    )
}

/// The build extensions the project declares: core extensions, and the
/// `<build><extensions>` and plugins with `<extensions>true</extensions>`
/// of its reactor POMs and their local parents. Polyglot's core extensions
/// have their own row, and os-maven-plugin is left out, since raeva sets
/// the properties it sets.
fn extensions_row(
    config: &Config,
    core: &Result<Vec<String>, String>,
    offline: bool,
) -> Option<Row> {
    const CHECK: &str = "build extensions";
    // A reactor that cannot be read fails the repository probes, and under
    // --offline this row. A file sync does not read only leaves the check
    // undone.
    let unreadable = |what: String| {
        Some(
            Row::new(
                CHECK,
                format!("not checked, so the project may load build extensions: {what}"),
                Outcome::Warn,
            )
            .with_code(WarningCode::BuildExtensions),
        )
    };
    let mut found = Vec::new();
    match core {
        Ok(core) => {
            let core: Vec<&str> = (core.iter())
                .filter(|key| !key.starts_with(&format!("{POLYGLOT_GROUP}:")))
                .filter(|key| *key != OS_MAVEN_PLUGIN)
                .map(String::as_str)
                .collect();
            if !core.is_empty() {
                found.push(format!(".mvn/extensions.xml: {}", core.join(", ")));
            }
        }
        Err(err) => return unreadable(format!(".mvn/extensions.xml cannot be read: {err}")),
    }
    let workspace = match rv_resolver::Workspace::discover_project(config, None) {
        Ok(workspace) => workspace,
        Err(err) => {
            let outcome = if offline {
                Outcome::Config
            } else {
                Outcome::Info
            };
            return Some(Row::new(
                CHECK,
                format!("not checked: pom.xml could not be read: {err}"),
                outcome,
            ));
        }
    };
    let root = workspace.root();
    let paths: Vec<PathBuf> = (workspace.modules().iter())
        .map(|module| module.pom_file().to_path_buf())
        .chain(workspace.local_parent_poms().iter().cloned())
        .collect();
    // Each module POM, then its local parents nearest first: a POM inherits
    // the plugin management of the ones after it.
    let lineages = (workspace.modules().iter())
        .map(|module| {
            std::iter::once(module.pom_file().to_path_buf())
                .chain(module.local_parents().iter().cloned())
                .collect::<Vec<_>>()
        })
        .chain(paths.iter().map(|path| vec![path.clone()]))
        .collect::<Vec<_>>();
    let mut poms = BTreeMap::new();
    for path in lineages.iter().flatten() {
        if !poms.contains_key(path) {
            match read_pom(path) {
                Ok(pom) => poms.insert(path.clone(), pom),
                Err(err) => {
                    return unreadable(format!("{} cannot be read: {err}", shown_path(root, path)));
                }
            };
        }
    }
    let mut declared = BTreeMap::<&PathBuf, Vec<String>>::new();
    for lineage in &lineages {
        for (at, path) in lineage.iter().enumerate() {
            if declared.contains_key(path) {
                continue;
            }
            let inherited: Vec<rv_maven_model::Plugin> = (lineage[at + 1..].iter())
                .flat_map(|parent| poms[parent].1.clone())
                .collect();
            let (pom, _) = poms.get_mut(path).expect("every POM of a lineage is read");
            let keys = match pom.declared_build_extensions(&inherited) {
                Ok(extensions) => (extensions.iter().map(rv_maven_model::Plugin::key))
                    .filter(|key| key != OS_MAVEN_PLUGIN)
                    .collect(),
                Err(err) => {
                    return unreadable(format!("{} cannot be read: {err}", shown_path(root, path)));
                }
            };
            declared.insert(path, keys);
        }
    }
    let mut seen = BTreeSet::new();
    for path in &paths {
        if seen.insert(path) && !declared[path].is_empty() {
            found.push(format!(
                "{}: {}",
                shown_path(root, path),
                declared[path].join(", ")
            ));
        }
    }
    if found.is_empty() {
        return None;
    }
    Some(
        Row::new(
            CHECK,
            format!(
                "{}; raeva does not run build extensions, so a model or dependency an extension \
                 changes is not what raeva locks",
                found.join("; ")
            ),
            Outcome::Warn,
        )
        .with_code(WarningCode::BuildExtensions),
    )
}

/// The POM at `path` with its plugin sections, and the plugin management
/// it passes on to a child.
fn read_pom(path: &Path) -> Result<(rv_maven_model::Pom, Vec<rv_maven_model::Plugin>), String> {
    let bytes = rv_config::read_project_input(path).map_err(|err| err.to_string())?;
    let xml = rv_maven_model::decode_pom(&bytes).map_err(|err| err.to_string())?;
    let mut pom = rv_maven_model::Pom::parse_with_plugins(&xml).map_err(|err| err.to_string())?;
    let managed = pom
        .inherited_plugin_management()
        .map_err(|err| err.to_string())?;
    Ok((pom, managed))
}

/// `path` relative to the reactor root, with forward slashes, or as it is
/// when it lies outside.
fn shown_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root).map_or_else(
        |_| path.display().to_string(),
        |relative| relative.to_string_lossy().replace('\\', "/"),
    )
}

/// The reactor selection, `-s` and `-gs` in `.mvn/maven.config`, which raeva
/// does not take from there, as sync warns with `SETTING_IGNORED`.
fn maven_config_row(mvn: &Path) -> Option<Row> {
    let path = mvn.join("maven.config");
    let text = rv_config::read_optional_project_input_string(&path).ok()??;
    let ignored = rv_config::maven_config::ignored_options(&text).ok()?;
    if ignored.is_empty() {
        return None;
    }
    let (selection, settings): (Vec<&str>, Vec<&str>) = (ignored.iter())
        .partition(|option| rv_config::maven_config::REACTOR_SELECTION.contains(option));
    let mut reasons = Vec::new();
    if !selection.is_empty() {
        reasons.push(format!(
            "{}, since raeva locks the whole reactor, so a module this build skips can still \
             fail the sync",
            selection.join(", ")
        ));
    }
    if !settings.is_empty() {
        reasons.push(format!(
            "{}, since raeva takes the settings file only from the command line or the user \
             configuration",
            settings.join(", ")
        ));
    }
    Some(
        Row::new(
            ".mvn/maven.config",
            format!("raeva ignores {}", reasons.join("; and ")),
            Outcome::Warn,
        )
        .with_code(WarningCode::SettingIgnored),
    )
}

/// The platforms raeva.lock records, and a warning when `raeva sync
/// --frozen` fails here, as for a lock that cannot be read or records no
/// section for this machine's platform, or fails on any other machine,
/// since it records only this one's. An unreadable lock's row gives the
/// next step a sync names for it.
fn platforms_row(lock: &LockRead, config: &Config) -> Row {
    const CHECK: &str = "lock platforms";
    let warn = |details: String, code| Row::new(CHECK, details, Outcome::Warn).with_code(code);
    let lock = match lock {
        Ok(lock) => lock,
        Err(err) => {
            let why = match err {
                crate::error::CliError::LockfileIncompatible { reason, .. } => reason.clone(),
                err => err.to_string(),
            };
            let mut details =
                format!("raeva.lock cannot be read, so raeva sync --frozen fails: {why}");
            for next in err
                .diagnose(&crate::error::HintEnv::for_config(config))
                .hints
            {
                details.push_str(&format!(". {next}"));
            }
            return warn(details, WarningCode::LockUnreadable);
        }
    };
    let recorded: BTreeSet<String> = (lock.platforms.iter())
        .map(|entry| entry.platform.without_jdk().to_string())
        .collect();
    let host = Platform::current()
        .ok()
        .map(|host| host.without_jdk().to_string());
    let listed = recorded.iter().cloned().collect::<Vec<_>>().join(", ");
    if host.as_ref().is_some_and(|host| recorded.contains(host))
        && let Some((reason, hint)) = crate::commands::sync::unlisted_host_jdk(config)
    {
        let details = format!("{reason}, so raeva sync --frozen fails here. {hint}");
        return warn(details, WarningCode::HostJdkNotLocked);
    }
    match host {
        Some(host) if !recorded.contains(&host) => {
            let records = match recorded.is_empty() {
                true => "no platform".to_string(),
                false => format!("only {listed}"),
            };
            warn(
                format!(
                    "raeva.lock records {records}, not this machine's {host}, so raeva sync \
                     --frozen and raeva export-m2 fail here; add it with raeva sync \
                     --platforms {host}"
                ),
                WarningCode::HostPlatformNotLocked,
            )
        }
        Some(host) if recorded.len() == 1 => {
            let other = if host == "linux-x86_64" {
                "macos-aarch64"
            } else {
                "linux-x86_64"
            };
            warn(
                format!(
                    "raeva.lock records only {host}, this machine's platform, so raeva sync \
                     --frozen fails on any other, such as a CI runner; lock each platform \
                     CI and developers use, such as with raeva sync --platforms \
                     {host},{other} ({DOCS}ci.md)"
                ),
                WarningCode::HostPlatformOnly,
            )
        }
        _ => Row::new(CHECK, format!("raeva.lock records {listed}"), Outcome::Info),
    }
}

/// The nearest directory at or above `root` that holds `.git`.
fn git_root(root: &Path) -> Option<PathBuf> {
    root.ancestors()
        .find(|dir| dir.join(".git").exists())
        .map(Path::to_path_buf)
}

/// Whether a CI file at the git root runs `raeva sync --frozen`, or
/// setup-raeva with `check: true`, which runs it.
fn ci_check(root: &Path, git_root: &Path, found: &mut Preflight) {
    const CHECK: &str = "CI check";
    let mut files: Vec<PathBuf> = CI_FILES.iter().map(|file| git_root.join(file)).collect();
    for dir in CI_DIRS {
        let Ok(entries) = std::fs::read_dir(git_root.join(dir)) else {
            continue;
        };
        let mut yaml: Vec<PathBuf> = (entries.flatten())
            .map(|entry| entry.path())
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "yml" || extension == "yaml")
            })
            .collect();
        yaml.sort();
        files.extend(yaml);
    }
    let mut checking = Vec::new();
    let mut unread = Vec::new();
    for path in &files {
        match rv_config::read_optional_project_input_string(path) {
            Ok(Some(text)) if runs_frozen_sync(&text) => checking.push(shown_path(git_root, path)),
            Ok(_) => {}
            Err(err) => unread.push(err.to_string()),
        }
    }
    if !checking.is_empty() {
        found.rows.push(Row::new(
            CHECK,
            format!("raeva sync --frozen runs in {}", checking.join(", ")),
            Outcome::Info,
        ));
        return;
    }
    if !unread.is_empty() {
        found.rows.push(Row::new(
            CHECK,
            format!("not checked, since {}", unread.join("; ")),
            Outcome::Inconclusive,
        ));
        return;
    }
    found.rows.push(
        Row::new(
            CHECK,
            format!(
                "no CI file runs raeva sync --frozen, so nothing checks raeva.lock against the \
                 POMs; a job to add is below ({DOCS}ci.md)"
            ),
            Outcome::Warn,
        )
        .with_code(WarningCode::CiCheckMissing),
    );
    // A CI job starts at the git root.
    let project = match shown_path(git_root, root) {
        dir if dir.is_empty() => String::new(),
        dir => format!("-C {} ", crate::commands::util::quote_word(&dir, false)),
    };
    found.snippets.push(Snippet {
        file: "CI",
        text: format!(
            "# With raeva {} installed ({DOCS}ci.md); on GitHub Actions,\n\
             # raeva-io/setup-raeva with `check: true` runs this.\n\
             raeva {project}sync --frozen\n",
            env!("CARGO_PKG_VERSION")
        ),
    });
}

/// Whether `text` has a setup-raeva step with `check: true` or a command
/// that runs `raeva ... sync --frozen`, also quoted, as a Jenkinsfile's
/// `sh '...'` is, or chained with `;`, `&&` or `|`.
fn runs_frozen_sync(text: &str) -> bool {
    let lines = logical_lines(text);
    // A step is a `-` line and the deeper lines after it.
    let setup_raeva = (lines.iter().enumerate())
        .filter(|(_, (_, line))| line.starts_with('-'))
        .any(|(at, (indent, _))| {
            let deeper = lines[at + 1..].iter().take_while(|(next, _)| next > indent);
            let entries = (lines[at..=at].iter().chain(deeper))
                .flat_map(|(_, line)| line.trim_start_matches(['-', ' ']).split(['{', ',', '}']))
                .filter_map(|entry| entry.split_once(':'))
                .map(|(key, value)| (key.trim(), value.trim().trim_matches(['"', '\''])));
            let has = |name: &str, holds: fn(&str) -> bool| {
                entries
                    .clone()
                    .any(|(key, value)| key == name && holds(value))
            };
            has("uses", |value| value.contains("setup-raeva"))
                && has("check", |value| value.eq_ignore_ascii_case("true"))
        });
    setup_raeva
        || (lines.iter())
            .flat_map(|(_, line)| line.split([';', '&', '|']))
            .any(|command| {
                let words: Vec<&str> = (command
                    .split(|c: char| c.is_whitespace() || "'\"`()".contains(c)))
                .filter(|word| !word.is_empty())
                .collect();
                let raeva = words.iter().position(|word| {
                    word.rsplit(['/', '\\'])
                        .next()
                        .is_some_and(|name| name == "raeva" || name == "raeva.exe")
                });
                raeva.is_some_and(|at| {
                    let rest = &words[at + 1..];
                    rest.contains(&"sync") && (rest.contains(&"--frozen") || rest.contains(&"-f"))
                })
            })
}

/// The lines of `text` with their indentation, without `#` comments and
/// `//` comment lines, a line that ends in `\` joined with the next, and a
/// folded YAML block (`>`) joined into the line that starts it.
fn logical_lines(text: &str) -> Vec<(usize, String)> {
    let mut physical = (text.lines())
        .filter_map(|line| {
            let code = line.trim_start();
            let comment = (code.match_indices('#'))
                .find(|(at, _)| code[..*at].chars().last().is_none_or(char::is_whitespace));
            let code = code[..comment.map_or(code.len(), |(at, _)| at)].trim_end();
            (!code.is_empty() && !code.starts_with("//"))
                .then(|| (line.len() - line.trim_start().len(), code))
        })
        .peekable();
    let mut lines = Vec::new();
    while let Some((indent, code)) = physical.next() {
        let mut line = code.to_owned();
        while line.ends_with('\\')
            && let Some((_, next)) = physical.next()
        {
            line.pop();
            line.push(' ');
            line.push_str(next);
        }
        let header = line.trim_end_matches(|c: char| "+-".contains(c) || c.is_ascii_digit());
        if header.ends_with(" >")
            && let Some(&(content, _)) = physical.peek().filter(|(next, _)| *next > indent)
        {
            line.truncate(header.len() - 1);
            while let Some((_, next)) = physical.next_if(|(next, _)| *next >= content) {
                line.push(' ');
                line.push_str(next);
            }
        }
        lines.push((indent, line));
    }
    lines
}

/// The `.gitattributes` files from the git root to the project, in git's
/// order, where a later matching line wins: whether raeva.lock ends up
/// marked as generated, and whether its merge ends up off, which docs/ci.md
/// says to undo.
fn gitattributes_check(root: &Path, git_root: &Path, found: &mut Preflight) {
    const CHECK: &str = ".gitattributes";
    let mut generated = false;
    let mut no_merge = None;
    let mut dirs: Vec<&Path> = root.ancestors().collect();
    if let Some(at) = dirs.iter().position(|dir| *dir == git_root) {
        dirs.truncate(at + 1);
    }
    for dir in dirs.into_iter().rev() {
        let path = dir.join(".gitattributes");
        let Ok(Some(text)) = rv_config::read_optional_project_input_string(&path) else {
            continue;
        };
        let lock = shown_path(dir, &root.join("raeva.lock"));
        for line in text.lines().map(str::trim) {
            let mut words = line.split_whitespace();
            let Some(pattern) = words.next().filter(|pattern| !pattern.starts_with('#')) else {
                continue;
            };
            if !matches_lock(pattern, &lock) {
                continue;
            }
            for attribute in words {
                match attribute {
                    "linguist-generated" | "linguist-generated=true" => generated = true,
                    "-linguist-generated" | "!linguist-generated" | "linguist-generated=false" => {
                        generated = false;
                    }
                    "-merge" | "binary" | "merge=binary" => {
                        no_merge = Some(format!("'{line}' in {}", shown_path(git_root, &path)));
                    }
                    "!merge" => no_merge = None,
                    _ if attribute == "merge" || attribute.starts_with("merge=") => no_merge = None,
                    _ => {}
                }
            }
        }
    }
    if let Some(line) = no_merge {
        found.rows.push(
            Row::new(
                CHECK,
                format!(
                    "{line} keeps git from merging raeva.lock; remove it, since raeva sync merges \
                     a conflicted lock ({DOCS}ci.md)"
                ),
                Outcome::Warn,
            )
            .with_code(WarningCode::LockMergeDisabled),
        );
    }
    if !generated {
        found.rows.push(
            Row::new(
                CHECK,
                format!(
                    "raeva.lock is not marked as generated, so pull request diffs show it in \
                     full; the line to add is below ({DOCS}ci.md)"
                ),
                Outcome::Info,
            )
            .with_code(WarningCode::LockNotMarkedGenerated),
        );
        found.snippets.push(Snippet {
            file: ".gitattributes",
            text: format!("{GITATTRIBUTES_LINE}\n"),
        });
    }
}

/// Whether a `.gitattributes` pattern names raeva.lock at `lock`, its path
/// from that file's directory: a pattern with a `/` names a file of that
/// directory, one without names the file in any directory. Only the
/// patterns that name raeva.lock by name or by `*` and `*.lock` are known.
fn matches_lock(pattern: &str, lock: &str) -> bool {
    let anchored = pattern.contains('/');
    let pattern = pattern.trim_start_matches('/');
    let name = match pattern.strip_prefix("**/") {
        Some(name) => name,
        None if anchored => {
            let (dir, name) = pattern.rsplit_once('/').unwrap_or(("", pattern));
            if dir != lock.rsplit_once('/').map_or("", |(dir, _)| dir) {
                return false;
            }
            name
        }
        None => pattern,
    };
    matches!(name, "raeva.lock" | "*.lock" | "*")
}

#[cfg(test)]
mod tests;
