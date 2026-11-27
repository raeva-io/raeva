use std::path::Path;

/// Convert a filesystem path to a forward-slash string, regardless of the
/// host OS path separator.
///
/// On POSIX systems this is a no-op. On Windows, `Path::display()` emits
/// backslashes which break cross-platform tooling that consumes JSON `"path"`
/// fields (e.g. shell scripts, Make targets). Replacing backslashes with
/// forward slashes matches what every Maven-adjacent tool expects.
pub(crate) fn path_to_forward_slashes(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

pub(crate) fn help_examples(examples: &[(&str, &str)]) -> String {
    let mut out = String::from("Examples:\n");
    for (args, comment) in examples {
        let command = format!("raeva {args}");
        if comment.is_empty() {
            out.push_str(&format!("  {command}\n"));
        } else {
            out.push_str(&format!("  {command:<35} # {comment}\n"));
        }
    }
    out
}

/// `word` as one literal argument for a POSIX shell, or for PowerShell on
/// Windows, quoted when it holds anything but path characters.
pub(crate) fn shell_word(word: &str) -> String {
    quote_word(word, cfg!(windows))
}

pub(crate) fn quote_word(word: &str, powershell: bool) -> String {
    let safe = if powershell {
        "\\/._-:=+@,"
    } else {
        "/._-:=+@,%"
    };
    if (word.chars()).all(|c| c.is_ascii_alphanumeric() || safe.contains(c)) {
        return word.to_string();
    }
    let mut quoted = String::from("'");
    for c in word.chars() {
        match c {
            '\'' if !powershell => quoted.push_str("'\\''"),
            // PowerShell ends a single-quoted string at any of these, and
            // reads one doubled as the character itself.
            '\'' | '\u{2018}' | '\u{2019}' | '\u{201A}' | '\u{201B}' if powershell => {
                quoted.push(c);
                quoted.push(c);
            }
            c => quoted.push(c),
        }
    }
    quoted.push('\'');
    quoted
}

/// Writes `contents` to `path` through a temporary file beside it, so a
/// reader never sees half a file. A path that names a device, a pipe or a
/// socket, or one of this process's open files, such as `/dev/stdout`, is
/// written directly instead: there is no file to replace, its directory may
/// not take a temporary file, and replacing the file stdout was redirected
/// to would leave stdout writing to the old one. Such a file is appended
/// to, so what the shell or raeva wrote to it before stays.
pub(crate) fn write_atomic(path: &Path, contents: &[u8]) -> crate::error::Result<()> {
    let io_error = |source| crate::error::CliError::io_at(path)(source);
    if names_open_file(path)
        || path
            .metadata()
            .is_ok_and(|meta| !meta.is_file() && !meta.is_dir())
    {
        use std::io::Write;
        let mut target = std::fs::OpenOptions::new()
            .append(true)
            .open(path)
            .map_err(io_error)?;
        return target
            .write_all(contents)
            .and_then(|()| target.flush())
            .map_err(io_error);
    }
    rv_fs::write_file_atomic(path, contents, rv_fs::NewFileAccess::Shared).map_err(io_error)
}

/// Whether `path` names a file descriptor of this process, as `/dev/stdout`,
/// `/dev/fd/N` and `/proc/self/fd/N` do, directly or through a symlink.
fn names_open_file(path: &Path) -> bool {
    if !cfg!(unix)
        || path
            .components()
            .any(|component| component == std::path::Component::ParentDir)
    {
        return false;
    }
    let is_fd = |path: &Path| {
        ["/dev/fd", "/proc/self/fd", "/dev/stdout", "/dev/stderr"]
            .iter()
            .any(|prefix| path.starts_with(prefix))
    };
    let mut current = path.to_path_buf();
    // `/dev/stdout` links to `/proc/self/fd/1`, which links to the file.
    for _ in 0..3 {
        if is_fd(&current) {
            return true;
        }
        match std::fs::read_link(&current) {
            Ok(target) if target.is_absolute() => current = target,
            Ok(target) => {
                current = current
                    .parent()
                    .map_or_else(|| target.clone(), |parent| parent.join(&target));
            }
            Err(_) => return false,
        }
    }
    false
}

/// The RFC 9562 version 8 UUID made of the first 16 bytes of `digest`.
pub(crate) fn uuid_v8(digest: &[u8]) -> String {
    let mut bytes: [u8; 16] = digest[..16].try_into().expect("16 bytes");
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = hex::encode(bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

pub(crate) fn count_dependencies<'a>(
    platforms: impl IntoIterator<Item = &'a rv_lock::LockPlatform>,
) -> usize {
    // Count unique coordinates across platforms rather than summing
    // per-platform package lists. A 2-platform lockfile that resolved
    // the same dep set would otherwise report 2× the real number,
    // misleading users about how many distinct artifacts `raeva sync`
    // resolved. Platform-specific (e.g. native binary) packages still
    // count once each because their classifier/coord differs.
    // Reactor modules are built and system files are on disk; neither is
    // resolved from a repository, so they do not count.
    let mut seen = std::collections::HashSet::new();
    for platform in platforms {
        seen.extend(platform.module_rows());
    }
    seen.len()
}

/// `group:artifact:version`, with the type and classifier only when the
/// artifact is not a plain jar.
pub(crate) fn display_coordinate(package: &rv_lock::LockModulePackage) -> String {
    if shown_type(package) == "jar" && package.coordinate.classifier().is_none() {
        return package.coordinate.gav.to_string();
    }
    package_coordinate(package)
}

/// `group:artifact:version:type[:classifier]`, with the Maven type the
/// package was declared with, as `mvn dependency:list` names it, and not
/// the extension raeva.lock's artifact rows use.
pub(crate) fn package_coordinate(package: &rv_lock::LockModulePackage) -> String {
    let coordinate = &package.coordinate;
    let text = format!("{}:{}", coordinate.gav, shown_type(package));
    match coordinate.classifier() {
        Some(classifier) => format!("{text}:{classifier}"),
        None => text,
    }
}

/// The Maven type, or the extension for a type that a coordinate cannot
/// carry so `raeva why` reads it back: one with `:`, whitespace or `%`.
fn shown_type(package: &rv_lock::LockModulePackage) -> &str {
    let type_ = package.maven_type();
    match type_.contains(|c: char| c == ':' || c == '%' || c.is_whitespace()) {
        true => package.coordinate.extension(),
        false => type_,
    }
}

pub(crate) fn module_roots(module: &rv_lock::LockModule, incoming: &[usize]) -> Vec<usize> {
    let packages = &module.packages;
    let direct = packages
        .iter()
        .any(|package| package.direct_scope.is_some());
    let roots: Vec<usize> = (0..packages.len())
        .filter(|&index| {
            if direct {
                packages[index].direct_scope.is_some()
            } else {
                incoming[index] == 0
            }
        })
        .collect();
    if roots.is_empty() {
        (0..packages.len()).collect()
    } else {
        roots
    }
}

/// Refuse an edge that names a package the module does not have.
pub(crate) fn check_edge(
    module: &rv_lock::LockModule,
    edge: &rv_lock::LockEdge,
) -> crate::error::Result<()> {
    let count = module.packages.len();
    if edge.from < count && edge.to < count {
        return Ok(());
    }
    Err(crate::error::CliError::LockfileDefect {
        details: format!(
            "edge out of bounds in module '{}': {} -> {}",
            module.path, edge.from, edge.to
        ),
    })
}

/// Up to three module directories, or how many there are.
pub(crate) fn modules_phrase(modules: &std::collections::BTreeSet<String>) -> String {
    if modules.len() > 3 {
        return format!("{} modules", modules.len());
    }
    join_and(modules.iter().map(|path| module_name(path)))
}

/// A module's directory, or its POM path where the file is not a pom.xml.
pub(crate) fn module_name(path: &str) -> String {
    match path {
        "pom.xml" => "the root module".to_string(),
        _ => path.strip_suffix("/pom.xml").unwrap_or(path).to_string(),
    }
}

/// `count` and the noun for it, such as `1 file` or `2 files`.
pub(crate) fn plural(count: usize, one: &str, many: &str) -> String {
    format!("{count} {}", if count == 1 { one } else { many })
}

pub(crate) fn join_and(items: impl IntoIterator<Item = String>) -> String {
    let items: Vec<String> = items.into_iter().collect();
    match items.as_slice() {
        [] => String::new(),
        [one] => one.clone(),
        [init @ .., last] => format!("{} and {last}", init.join(", ")),
    }
}

pub(crate) fn read_lockfile(config: &rv_config::Config) -> crate::error::Result<rv_lock::Lockfile> {
    read_lockfile_at(&config.lock_path)
}

/// Missing, dangling, and non-file lockfiles each get their own diagnostic
/// before `Lockfile::read` runs. Both follow symlinks.
pub(crate) fn read_lockfile_at(path: &std::path::Path) -> crate::error::Result<rv_lock::Lockfile> {
    use crate::error::CliError;
    let path_buf = path.to_path_buf();
    match path.metadata() {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Err(CliError::LockfileMissing {
                sync_creates: path.with_file_name("pom.xml").is_file(),
                path: path_buf,
                reactor: None,
            });
        }
        Err(source) => return Err(CliError::io_at(path_buf)(source)),
        Ok(meta) if !meta.is_file() => return Err(CliError::LockfileNotAFile { path: path_buf }),
        Ok(_) => {}
    }
    rv_lock::Lockfile::read(path).map_err(|err| {
        if let rv_lock::LockError::UnsupportedSchema { found, expected } = err
            && found > expected
        {
            CliError::LockfileTooNew { found, expected }
        } else if !matches!(err, rv_lock::LockError::UnsupportedSchema { .. })
            && let Some(found) = newer_schema(path)
        {
            // A conflict or newer syntax stops the read before its version.
            CliError::LockfileTooNew {
                found,
                expected: rv_lock::LOCKFILE_SCHEMA_VERSION,
            }
        } else if err.is_incompatible_lockfile() {
            // What a plain sync reads it as: within the cap and UTF-8, and
            // with pins it keeps, which agree.
            let text = (!matches!(err, rv_lock::LockError::TooLarge { .. }))
                .then(|| {
                    use std::io::Read;
                    let mut bytes = Vec::new();
                    let file = std::fs::File::open(path).ok()?;
                    let read = file
                        .take(rv_lock::MAX_LOCKFILE_BYTES + 1)
                        .read_to_end(&mut bytes)
                        .ok()?;
                    (read as u64 <= rv_lock::MAX_LOCKFILE_BYTES).then_some(())?;
                    String::from_utf8(bytes).ok()
                })
                .flatten();
            let regenerate = text.map(|text| {
                rv_lock::conflict::recover_pins(&text).is_ok_and(|versions| {
                    let locks: Vec<_> = versions.iter().map(|(_, lock)| lock).collect();
                    rv_lock::conflict::disagreements(&locks).is_empty()
                })
            });
            CliError::LockfileIncompatible {
                reason: err.to_string(),
                regenerate,
            }
        } else {
            // The only non-incompatible LockError is Io. Surface it as IO so
            // scripts see exit 1 / code IO, not CONFIG.
            match err {
                rv_lock::LockError::Io { source, .. } => CliError::io_at(path_buf)(source),
                other => CliError::Lock(other),
            }
        }
    })
}

/// Whether raeva.lock at `path` holds the text raeva writes for `lock`,
/// checked on a thread of its own while the caller goes on.
pub(crate) fn check_written(
    lock: &rv_lock::Lockfile,
    path: &std::path::Path,
) -> std::thread::JoinHandle<bool> {
    let (lock, path) = (lock.clone(), path.to_path_buf());
    std::thread::spawn(move || lock.is_written_at(&path).unwrap_or(false))
}

/// What `--frozen` and `raeva lock verify` say of a raeva.lock
/// [`check_written`] finds other text in. Text raeva would not write, such
/// as comments, another order or other spellings, reads as the same lock
/// but shows a reviewer something else.
pub(crate) fn not_written(written: std::thread::JoinHandle<bool>) -> crate::error::Result<()> {
    if written.join().unwrap_or(false) {
        return Ok(());
    }
    Err(crate::error::CliError::lockfile_mismatch_with(
        "raeva.lock is not the text raeva writes for what it holds: a hand edit or another \
         tool changed it",
        "Run 'raeva sync' to rewrite it, review the diff, and commit the result",
    ))
}

/// The highest top-level `schema_version` above this raeva's that the lock
/// at `path` declares, on either side of a merge conflict.
fn newer_schema(path: &std::path::Path) -> Option<u32> {
    use std::io::Read;
    let mut bytes = Vec::new();
    (std::fs::File::open(path).ok()?)
        .take(rv_lock::MAX_LOCKFILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > rv_lock::MAX_LOCKFILE_BYTES {
        return None;
    }
    rv_lock::conflict::newer_schema(&String::from_utf8_lossy(&bytes))
}

/// Each module's POM path with the repositories and the plugin
/// repositories it declares.
type DeclaredRepositories = Vec<(String, Vec<rv_repo::Repository>, Vec<rv_repo::Repository>)>;

/// The repositories the project's own POMs declare, the root `pom.xml` and
/// its reactor modules, for each target `[lock] jdks` gives this platform:
/// every module's POM path with the repositories and plugin repositories it
/// declares, in reactor order. Repositories declared only by dependency POMs are not among them.
/// Discovery reads local files only.
pub(crate) fn project_declared_repositories(
    config: &rv_config::Config,
) -> Result<Vec<DeclaredRepositories>, rv_resolver::WorkspaceError> {
    let base = rv_lock::Platform::current().ok();
    let targets: Vec<Option<rv_lock::Platform>> = match (&base, config.lock.jdks.is_empty()) {
        (Some(platform), false) => config
            .lock
            .jdks
            .iter()
            .map(|jdk| Some(platform.clone().with_jdk(jdk.clone())))
            .collect(),
        (platform, _) => vec![platform.clone()],
    };
    targets
        .iter()
        .map(|target| {
            let workspace = rv_resolver::Workspace::discover_project(config, target.as_ref())?;
            Ok(workspace
                .modules()
                .iter()
                .map(|module| {
                    let declared = |repositories: &[rv_maven_model::Repository]| {
                        (repositories.iter())
                            .filter(|declared| declared.root_declared)
                            .map(rv_repo::Repository::from)
                            .collect()
                    };
                    let descriptor = &module.descriptor;
                    (
                        module.pom_path.clone(),
                        declared(&descriptor.repositories),
                        declared(&descriptor.plugin_repositories),
                    )
                })
                .collect())
        })
        .collect()
}

pub(crate) fn parse_scope(value: &str) -> Result<rv_lock::Scope, String> {
    value.trim().to_ascii_lowercase().parse().map_err(|_| {
        "expected compile, runtime, test, provided, system, import or compile-only".to_string()
    })
}

/// The platforms `--platforms` accepts, besides the one raeva runs on. Each is
/// the name `raeva` reports on that platform, so a lock written for it is the
/// one a machine there checks.
pub(crate) const SUPPORTED_PLATFORMS: &[&str] = &[
    "linux-x86_64",
    "linux-aarch64",
    "macos-x86_64",
    "macos-aarch64",
    "windows-x86_64",
    "windows-aarch64",
];

/// A `--platforms` value. Surrounding whitespace is ignored here, where a
/// shell or a `,`-separated list can add it; raeva.lock spells a platform
/// exactly. Only [`SUPPORTED_PLATFORMS`] and the current platform are
/// accepted: a lock section for any other name, such as `darwin-aarch64`,
/// would never be the one a machine checks.
pub(crate) fn parse_platform(value: &str) -> Result<rv_lock::Platform, String> {
    let value = value.trim();
    let current = rv_lock::Platform::current().map_err(|err| err.to_string())?;
    if SUPPORTED_PLATFORMS.contains(&value) || value == current.to_string() {
        return value
            .parse::<rv_lock::Platform>()
            .map_err(|err| err.to_string());
    }
    let mut supported: Vec<String> = SUPPORTED_PLATFORMS
        .iter()
        .map(ToString::to_string)
        .collect();
    if !supported.contains(&current.to_string()) {
        supported.push(current.to_string());
    }
    let shown = crate::output::inline_text(value);
    let mut message = format!("unsupported platform '{shown}'");
    match platform_suggestion(value).filter(|name| supported.contains(name)) {
        Some(suggestion) => message.push_str(&format!("; did you mean '{suggestion}'?")),
        None => message.push('.'),
    }
    message.push_str(&format!(" Supported platforms: {}", supported.join(", ")));
    Err(message)
}

/// The supported name for a common other spelling of a platform, such as
/// the os-maven-plugin's `osx-aarch_64` or Go's `darwin-arm64`.
fn platform_suggestion(value: &str) -> Option<String> {
    let lower = value.to_ascii_lowercase();
    let (os, arch) = lower.split_once(['-', '_', '/'])?;
    let os = match os {
        "linux" => "linux",
        "macos" | "darwin" | "osx" | "mac" | "macosx" => "macos",
        "windows" | "win" | "win32" | "win64" => "windows",
        _ => return None,
    };
    let arch = match arch {
        "x86_64" | "x86-64" | "amd64" | "x64" => "x86_64",
        "aarch64" | "aarch_64" | "arm64" => "aarch64",
        _ => return None,
    };
    Some(format!("{os}-{arch}"))
}

pub(crate) fn select_platform<'a>(
    lock: &'a rv_lock::Lockfile,
    host_jdk: Option<&str>,
) -> Result<&'a rv_lock::LockPlatform, crate::error::CliError> {
    let current = rv_lock::Platform::current()?;
    if let Some(entry) = lock.platforms.iter().find(|entry| {
        entry.platform == current
            || (entry.platform.without_jdk() == current
                && entry.platform.jdk().is_some_and(|jdk| {
                    host_jdk.is_some_and(|host| rv_config::jdk_matches_target(jdk, host))
                }))
    }) {
        return Ok(entry);
    }
    if let Some(fallback) = lock
        .platforms
        .iter()
        .find(|entry| entry.platform.without_jdk() == current)
        .or_else(|| lock.platforms.first())
    {
        // A `sec_code` warning reaches the JSON envelope and, in human mode,
        // the warning summary printed at exit. Swapping platforms silently
        // would mask "wrong arch jar" outcomes.
        let current_str = match host_jdk {
            Some(host) if fallback.platform.jdk().is_some() => current.with_jdk(host).to_string(),
            None if fallback.platform.jdk().is_some() => format!("{current} (JDK unknown)"),
            _ => current.to_string(),
        };
        let fallback_str = fallback.platform.to_string();
        tracing::warn!(
            sec_code = "PLATFORM_FALLBACK",
            current = %current_str,
            fallback = %fallback_str,
            "platform '{current_str}' not found in lockfile; using '{fallback_str}'"
        );
        return Ok(fallback);
    }
    Err(crate::error::CliError::PlatformMissing {
        platform: current.to_string(),
        recorded: Vec::new(),
        frozen: false,
    })
}

#[cfg(all(test, unix))]
mod tests {
    #[test]
    fn a_newer_schema_is_read_only_from_top_level_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("raeva.lock");
        let current = rv_lock::LOCKFILE_SCHEMA_VERSION;
        let newer = current + 1;
        let scan = |text: String| {
            std::fs::write(&path, text).unwrap();
            super::newer_schema(&path)
        };
        let conflict = format!(
            "<<<<<<< ours\nschema_version = {current}\n[resolution]\nx = 1\n=======\nschema_version = {newer}\n# '''\n[resolution]\nx = 2\n>>>>>>> theirs\n"
        );
        assert_eq!(scan(conflict.clone()), Some(newer));
        let long = (conflict.replace("<<<<<<<", "<<<<<<<<<"))
            .replace("=======", "=========")
            .replace(">>>>>>>", ">>>>>>>>>");
        assert_eq!(scan(long), Some(newer));
        let stray = format!("schema_version = {newer}\n[resolution]\n=======\nx = 1\n");
        assert_eq!(scan(stray), Some(newer));
        let quoted = format!(
            "schema_version = {current}\nnote = '''\n\"\"\"\nschema_version = {newer}\n'''\n"
        );
        assert_eq!(scan(quoted), None);
        let nested = format!("schema_version = {current}\n[extra]\nschema_version = {newer}\n");
        assert_eq!(scan(nested), None);
    }

    use super::{read_lockfile, write_atomic};

    /// A reactor module another module depends on and a system file are not
    /// resolved, so the count is the external artifacts `raeva lock info`
    /// gives.
    #[test]
    fn reactor_modules_are_not_counted_as_dependencies() {
        use rv_lock::{LockArtifact, LockModulePackage, LockPlatform, Lockfile, Platform, Scope};
        use rv_maven_types::{ArtifactCoord, Gav};
        let coord = |artifact: &str| ArtifactCoord::new("g", artifact, "1", "jar", None);
        let mut platform = LockPlatform::single_module(
            Platform::new("linux", "x86_64").expect("platform"),
            Gav::new("g", "app", "1"),
            "jar",
            vec![LockArtifact::new(coord("lib"), "https://repo.example/")],
        );
        let mut sibling = LockModulePackage::new(coord("core"), Some(Scope::Compile));
        sibling.workspace_module = Some("core/pom.xml".to_string());
        platform.modules[0].packages.push(sibling);
        let mut system = LockModulePackage::new(coord("tools"), Some(Scope::System));
        system.system_path = Some("lib/tools.jar".to_string());
        platform.modules[0].packages.push(system);
        let mut lock = Lockfile::new();
        lock.platforms.push(platform);
        assert_eq!(super::count_dependencies(&lock.platforms), 1);
    }
    use crate::error::CliError;
    use rv_config::{Config, ResolvedPaths};
    use tempfile::TempDir;

    fn config_for(project_root: &std::path::Path) -> Config {
        let raeva_home = project_root.join(".raeva");
        let paths = ResolvedPaths::from_raeva_home(&raeva_home);
        Config::for_testing_with_repos(project_root.to_path_buf(), paths, Vec::new())
    }

    #[test]
    fn read_lockfile_follows_symlinks_and_reports_dangling_ones_as_missing() {
        let tmp = TempDir::new().expect("tempdir");
        let config = config_for(tmp.path());
        std::os::unix::fs::symlink(tmp.path().join("gone.lock"), &config.lock_path)
            .expect("dangling symlink");
        let err = read_lockfile(&config).expect_err("expected LockfileMissing");
        assert!(matches!(err, CliError::LockfileMissing { .. }), "{err:?}");

        std::fs::remove_file(&config.lock_path).expect("remove symlink");
        std::fs::create_dir(tmp.path().join("dir.lock")).expect("mkdir");
        std::os::unix::fs::symlink(tmp.path().join("dir.lock"), &config.lock_path)
            .expect("directory symlink");
        let err = read_lockfile(&config).expect_err("expected LockfileNotAFile");
        assert!(matches!(err, CliError::LockfileNotAFile { .. }), "{err:?}");
    }

    #[test]
    fn write_atomic_creates_files_with_the_umask_mode() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new().expect("tempdir");
        let plain = tmp.path().join("plain");
        std::fs::File::create(&plain).expect("create plain file");
        let path = tmp.path().join("bom.json");
        write_atomic(&path, b"{}").expect("atomic write");

        let mode = |path: &std::path::Path| {
            std::fs::metadata(path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777
        };
        assert_eq!(mode(&path), mode(&plain));
    }
}

#[cfg(test)]
mod parse_tests {
    #[test]
    fn shell_words_quote_what_the_shell_would_expand() {
        use super::quote_word;
        for powershell in [false, true] {
            assert_eq!(
                quote_word("-Dmaven.repo.local=/a/b", powershell),
                "-Dmaven.repo.local=/a/b"
            );
        }
        assert_eq!(quote_word("/my repo/$(x)", false), "'/my repo/$(x)'");
        assert_eq!(quote_word(r"/it's\", false), r"'/it'\''s\'");
        assert_eq!(quote_word(r"C:\a\b", true), r"C:\a\b");
        assert_eq!(quote_word(r"C:\it's $(x)", true), r"'C:\it''s $(x)'");
        assert_eq!(
            quote_word("C:\\\u{2019}$(x)\u{2018}", true),
            "'C:\\\u{2019}\u{2019}$(x)\u{2018}\u{2018}'"
        );
    }

    #[test]
    fn parse_scope_ignores_case_and_surrounding_space() {
        assert_eq!(
            super::parse_scope(" Compile ").expect("compile"),
            rv_lock::Scope::Compile
        );
        assert_eq!(
            super::parse_scope("TEST").expect("test"),
            rv_lock::Scope::Test
        );
        assert_eq!(
            super::parse_scope("optional"),
            Err(
                "expected compile, runtime, test, provided, system, import or compile-only"
                    .to_string()
            )
        );
        assert_eq!(
            super::parse_scope("compile-only").expect("compile-only"),
            rv_lock::Scope::CompileOnly
        );
        assert!(super::parse_scope("").is_err());
    }
}
