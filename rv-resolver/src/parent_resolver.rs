//! Parent POM resolution: local `<relativePath>`, remote fetch with the
//! missing-parent cache, and activation-context construction.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rv_config::{Config, Platform};
use rv_maven_model::{ActivationContext, Parent, Pom, PomError};
use rv_version::{Coord, Version};

use crate::context::{MissingParentKey, ResolveContext};
use crate::util::pom_matches_parent;

/// Pluggable remote POM fetcher; lets tests stub the network without
/// spinning a real repo client. One production impl (`RepoBackendFetcher`);
/// test-only mock inline in the test module below.
pub(crate) trait RemotePomFetcher: Clone {
    /// `None` when the fetcher has no associated context (test mocks that
    /// never trigger the missing-parent cache path).
    fn context(&self) -> Option<&ResolveContext> {
        None
    }

    /// Probed before the missing-parent cache and remote fetching.
    fn fetch_local_pom_by_coord(&self, _coord: &Coord) -> Result<Option<Pom>, PomError> {
        Ok(None)
    }

    fn fetch_pom_by_coord(&self, coord: &Coord) -> Result<Option<Pom>, PomError>;
}

#[derive(Clone)]
pub(crate) struct ParentResolverBase<F: RemotePomFetcher> {
    pub(crate) base_dir: Option<PathBuf>,
    pub(crate) fetcher: F,
    pub(crate) strict: bool,
    /// Reject `<relativePath>` values that escape this root. `None` skips
    /// the containment check (legacy permissive behavior).
    pub(crate) project_root: Option<PathBuf>,
}

/// Validate the parsed POM matches `parent` and resolve any nested
/// `<parent>/<relativePath>` to absolute so the walk continues correctly.
fn read_and_validate_pom(
    path: &Path,
    contents: &str,
    parent: &Parent,
    suppress_logs: bool,
) -> Option<Pom> {
    let mut pom = match Pom::parse(contents) {
        Ok(pom) => pom,
        Err(e) => {
            if !suppress_logs {
                tracing::warn!(
                    "Failed to parse local parent POM at {}: {}",
                    path.display(),
                    e
                );
            }
            return None;
        }
    };

    if !pom_matches_parent(&pom, parent) {
        if !suppress_logs {
            tracing::debug!(
                "Local parent POM at {} does not match requested parent coordinates",
                path.display()
            );
        }
        return None;
    }

    if let Some(parent_ref) = &mut pom.parent {
        let relative = parent_ref.relative_path.as_deref().unwrap_or("../pom.xml");
        if !relative.is_empty()
            && let Some(parent_dir) = path.parent()
        {
            let resolved = parent_dir.join(relative);
            parent_ref.relative_path = Some(resolved.to_string_lossy().to_string());
        }
    }
    Some(pom)
}

fn load_local_parent_at(
    base_dir: Option<&Path>,
    project_root: Option<&Path>,
    parent: &Parent,
) -> Option<Pom> {
    let base_dir = base_dir?;
    let relative = match parent.relative_path.as_deref() {
        Some("") => return None,
        Some(path) => path,
        None => "../pom.xml",
    };
    let mut path = base_dir.join(relative);

    // Reject `<relativePath>` values that escape the project tree (e.g.
    // `<relativePath>../../../../etc/passwd</relativePath>`); fall through
    // to remote resolution.
    if let Some(root) = project_root
        && !path_within_root(&path, root)
    {
        tracing::debug!(
            relative_path = %relative,
            "relativePath escapes project root; falling back to remote resolution"
        );
        return None;
    }

    if let Ok(metadata) = std::fs::metadata(&path)
        && metadata.is_dir()
    {
        path.push("pom.xml");
    }

    match std::fs::read_to_string(&path) {
        Ok(contents) => read_and_validate_pom(&path, &contents, parent, false),
        Err(e) if e.kind() == std::io::ErrorKind::IsADirectory => {
            // Pre-check missed a directory (TOCTOU); retry with pom.xml appended.
            path.push("pom.xml");
            let contents = std::fs::read_to_string(&path).ok()?;
            read_and_validate_pom(&path, &contents, parent, true)
        }
        Err(e) => {
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(
                    "Failed to read local parent POM at {}: {}",
                    path.display(),
                    e
                );
            }
            None
        }
    }
}

impl<F: RemotePomFetcher + Sync> ParentResolverBase<F> {
    pub fn new(base_dir: Option<PathBuf>, fetcher: F, strict: bool) -> Self {
        // The containment check in `load_local_parent_at` fires only when
        // `project_root.is_some()`. Deriving the root from `base_dir` makes the
        // check unavoidable at compile time whenever local resolution is
        // possible.
        let project_root = base_dir.clone();
        Self {
            base_dir,
            fetcher,
            strict,
            project_root,
        }
    }

    /// Load a parent POM from `<relativePath>` (defaults to `../pom.xml`),
    /// parse it, and validate the coordinates match.
    pub fn load_local_parent(&self, parent: &Parent) -> Option<Pom> {
        load_local_parent_at(
            self.base_dir.as_deref(),
            self.project_root.as_deref(),
            parent,
        )
    }

    pub fn fetch_pom_with_cache(&self, coord: Coord) -> Result<Option<Pom>, PomError> {
        if let Some(pom) = self.fetcher.fetch_local_pom_by_coord(&coord)? {
            return Ok(Some(pom));
        }

        let ctx = self.fetcher.context();
        let missing_key: MissingParentKey = (
            Arc::from(coord.group_id.as_str()),
            Arc::from(coord.artifact_id.as_str()),
            Arc::from(coord.version.as_str()),
        );
        if let Some(ctx) = ctx
            && ctx.is_parent_missing(&missing_key)
        {
            tracing::debug!(
                group_id = %coord.group_id,
                artifact_id = %coord.artifact_id,
                version = %coord.version,
                "Parent POM known to be missing (cached)"
            );
            return Ok(None);
        }

        match self.fetcher.fetch_pom_by_coord(&coord) {
            Ok(Some(pom)) => Ok(Some(pom)),
            Ok(None) => {
                if let Some(ctx) = ctx {
                    ctx.mark_parent_missing(missing_key);
                }
                tracing::debug!(
                    group_id = %coord.group_id,
                    artifact_id = %coord.artifact_id,
                    version = %coord.version,
                    "Parent POM not found, caching as missing"
                );
                Ok(None)
            }
            Err(e) => {
                if self.strict {
                    Err(e)
                } else {
                    // Non-strict mode: treat transient/lookup errors as
                    // missing so inheritance can fall back to the parent
                    // declaration's groupId/version.
                    tracing::warn!(
                        group_id = %coord.group_id,
                        artifact_id = %coord.artifact_id,
                        version = %coord.version,
                        error = %e,
                        "Parent POM fetch failed, treating as missing (non-strict mode)"
                    );
                    Ok(None)
                }
            }
        }
    }

    pub fn resolve_parent(&self, parent: &Parent) -> Result<Option<Pom>, PomError> {
        if let Some(pom) = self.load_local_parent(parent) {
            return Ok(Some(pom));
        }
        let version = Version::parse(&parent.version)
            .map_err(|err| PomError::InvalidModel(err.to_string()))?;
        let coord = Coord {
            group_id: parent.group_id.clone().into(),
            artifact_id: parent.artifact_id.clone().into(),
            version,
            packaging: Some("pom".to_string()),
            classifier: None,
        };
        self.fetch_pom_with_cache(coord)
    }

    pub fn resolve_import_pom(
        &self,
        group_id: &str,
        artifact_id: &str,
        version: &str,
        type_: Option<&str>,
        classifier: Option<&str>,
    ) -> Result<Option<Pom>, PomError> {
        let version =
            Version::parse(version).map_err(|err| PomError::InvalidModel(err.to_string()))?;
        let packaging = type_.filter(|value| !value.is_empty()).map(str::to_string);
        let classifier = classifier
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        let coord = Coord {
            group_id: group_id.into(),
            artifact_id: artifact_id.into(),
            version,
            packaging,
            classifier,
        };
        self.fetch_pom_with_cache(coord)
    }
}

/// True when `candidate` resolves inside `root`. Canonicalizes the deepest
/// existing prefix so symlink targets are honored; fails closed (returns
/// false) when canonicalization fails.
fn path_within_root(candidate: &Path, root: &Path) -> bool {
    let Ok(root_canonical) = rv_config::canonicalize_existing_prefix(root) else {
        return false;
    };
    let Ok(candidate_canonical) = rv_config::canonicalize_existing_prefix(candidate) else {
        return false;
    };
    candidate_canonical.starts_with(&root_canonical)
}

/// Parse `.mvn/maven.config` for CI-friendly `-Drevision=...` properties.
/// One arg per line or space-separated; bare `-Dkey` becomes `key=true`.
#[cfg(test)]
pub(crate) fn parse_maven_config(project_root: &Path) -> HashMap<String, String> {
    let config_path = project_root.join(".mvn").join("maven.config");
    let content = match std::fs::read_to_string(&config_path) {
        Ok(content) => content,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return HashMap::new(),
        Err(err) => {
            tracing::warn!(
                path = %config_path.display(),
                error = %err,
                "failed to read .mvn/maven.config; ignoring"
            );
            return HashMap::new();
        }
    };
    parse_maven_config_content(&content)
}

/// Async sister of [`parse_maven_config`]; use on hot async paths to avoid
/// blocking the executor on the (typically tiny) config read.
pub(crate) async fn parse_maven_config_async(project_root: &Path) -> HashMap<String, String> {
    let config_path = project_root.join(".mvn").join("maven.config");
    let content = match tokio::fs::read_to_string(&config_path).await {
        Ok(content) => content,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return HashMap::new(),
        Err(err) => {
            tracing::warn!(
                path = %config_path.display(),
                error = %err,
                "failed to read .mvn/maven.config; ignoring"
            );
            return HashMap::new();
        }
    };
    parse_maven_config_content(&content)
}

fn parse_maven_config_content(content: &str) -> HashMap<String, String> {
    let mut properties = HashMap::new();
    for token in content.split_whitespace() {
        if let Some(rest) = token.strip_prefix("-D") {
            if let Some((key, value)) = rest.split_once('=') {
                properties.insert(key.to_string(), value.to_string());
            } else if !rest.is_empty() {
                properties.insert(rest.to_string(), "true".to_string());
            }
        }
    }
    if !properties.is_empty() {
        tracing::debug!(
            count = properties.len(),
            "Loaded properties from .mvn/maven.config"
        );
    }
    properties
}

#[cfg(test)]
pub(crate) fn build_activation_context(
    base_dir: Option<PathBuf>,
    config: &Config,
    target_platform: Option<&Platform>,
) -> ActivationContext {
    let maven_config_props = base_dir
        .as_deref()
        .map(parse_maven_config)
        .unwrap_or_default();
    build_activation_context_with_props(base_dir, config, target_platform, maven_config_props)
}

/// Async variant of [`build_activation_context`] that reads
/// `.mvn/maven.config` without blocking the executor.
///
/// `target_platform` is the platform being resolved *for* (the per-`--platforms`
/// pass), not the host. Passing `None` falls back to the host platform.
pub async fn build_activation_context_async(
    base_dir: Option<PathBuf>,
    config: &Config,
    target_platform: Option<&Platform>,
) -> ActivationContext {
    let maven_config_props = match base_dir.as_deref() {
        Some(base) => parse_maven_config_async(base).await,
        None => HashMap::new(),
    };
    build_activation_context_with_props(base_dir, config, target_platform, maven_config_props)
}

fn build_activation_context_with_props(
    base_dir: Option<PathBuf>,
    config: &Config,
    target_platform: Option<&Platform>,
    maven_config_props: HashMap<String, String>,
) -> ActivationContext {
    let mut ctx = ActivationContext::from_system();

    // #5: during a `--platforms` cross-build the profile-activation OS must be
    // the TARGET platform, not the host. Maven activates `<os>` profiles
    // against the JVM `os.name`/`os.arch` of the build target; resolving for
    // `macos-aarch64` on a Linux CI box must activate macOS profiles, not
    // Linux ones, or the macOS-only deps are silently dropped. Prefer the
    // threaded target platform and fall back to the host only when none was
    // supplied.
    let platform = match target_platform {
        Some(target) => Some(target.clone()),
        None => Platform::current().ok(),
    };
    if let Some(platform) = platform.as_ref() {
        let os_name = rust_os_to_maven_name(platform.os());
        let os_arch = platform.arch().to_string();
        ctx.os_family = maven_os_family(platform.os()).map(str::to_string);
        ctx.os_name = Some(os_name.clone());
        ctx.os_arch = Some(os_arch.clone());
        ctx.properties.insert("os.name".to_string(), os_name);
        ctx.properties.insert("os.arch".to_string(), os_arch);
        match ctx.os_family.as_ref() {
            Some(family) => {
                ctx.properties
                    .insert("os.family".to_string(), family.clone());
            }
            None => {
                ctx.properties.remove("os.family");
            }
        }
    }

    for (key, value) in maven_config_props {
        ctx.properties.insert(key, value);
    }
    ctx.base_dir = base_dir;
    ctx.local_repository = config.local_repository().map(|p| p.to_path_buf());
    ctx.active_profiles = config.active_profiles().to_vec();
    ctx.inactive_profiles = config.inactive_profiles.clone();
    ctx
}

/// Maps a Rust `std::env::consts::OS`-style name (as carried by [`Platform`])
/// to the Maven/JVM `os.name` value that `<activation><os><name>` profiles are
/// matched against. Mirrors the private mapping in `rv_maven_model`; kept here
/// so the resolver can build a TARGET-platform activation context without a
/// host-only call to `ActivationContext::from_system`. (A shared public helper
/// in `rv_maven_model` would let both sides drop their copy; see workstream
/// notes.)
fn rust_os_to_maven_name(rust_os: &str) -> String {
    match rust_os {
        "macos" => "mac os x",
        "linux" => "linux",
        "windows" => "windows",
        "freebsd" => "freebsd",
        "openbsd" => "openbsd",
        "netbsd" => "netbsd",
        "solaris" | "illumos" => "sunos",
        "aix" => "aix",
        other => other,
    }
    .to_string()
}

/// Maven `os.family` for a Rust OS name. Matches `rv_maven_model`'s family
/// detection so a TARGET-platform context activates the right `<family>`.
fn maven_os_family(rust_os: &str) -> Option<&'static str> {
    match rust_os {
        "windows" => Some("windows"),
        "macos" => Some("mac"),
        "linux" | "freebsd" | "openbsd" | "netbsd" | "solaris" | "illumos" | "aix" => Some("unix"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rv_config::ResolvedPaths;

    #[derive(Clone)]
    struct MockFetcher;
    impl RemotePomFetcher for MockFetcher {
        fn fetch_pom_by_coord(&self, _coord: &Coord) -> Result<Option<Pom>, PomError> {
            Ok(None)
        }
    }

    fn pom_xml(artifact_id: &str) -> String {
        format!(
            r#"<project>
                <modelVersion>4.0.0</modelVersion>
                <groupId>com.example</groupId>
                <artifactId>{artifact_id}</artifactId>
                <version>1.0.0</version>
                <packaging>pom</packaging>
            </project>"#
        )
    }

    #[test]
    fn build_activation_context_sets_base_dir() {
        let paths = ResolvedPaths::discover().expect("paths");
        let config = Config::for_testing_with_repos(PathBuf::from("."), paths, Vec::new());
        let base_dir = Some(PathBuf::from("/test/dir"));

        let ctx = build_activation_context(base_dir.clone(), &config, None);
        assert_eq!(ctx.base_dir, base_dir);
    }

    #[test]
    fn build_activation_context_sets_platform_properties() {
        let paths = ResolvedPaths::discover().expect("paths");
        let config = Config::for_testing_with_repos(PathBuf::from("."), paths, Vec::new());

        let ctx = build_activation_context(None, &config, None);

        let Ok(platform) = Platform::current() else {
            return;
        };
        // `os_name` is the Maven/JVM-mapped name (e.g. "mac os x"), not the raw
        // Rust os ("macos"); `os_arch` passes through unchanged.
        let expected_os_name = rust_os_to_maven_name(platform.os());
        assert_eq!(ctx.os_name.as_deref(), Some(expected_os_name.as_str()));
        assert_eq!(ctx.os_arch.as_deref(), Some(platform.arch()));
        assert_eq!(
            ctx.properties.get("os.name").map(String::as_str),
            Some(expected_os_name.as_str())
        );
        assert_eq!(
            ctx.properties.get("os.arch").map(String::as_str),
            Some(platform.arch())
        );
    }

    /// #5: a TARGET platform threaded into the builder drives os.name/os.arch
    /// and os.family, regardless of the host the resolver runs on. This is what
    /// makes `--platforms macos-aarch64` activate macOS profiles on a Linux CI.
    #[test]
    fn build_activation_context_uses_target_platform() {
        let paths = ResolvedPaths::discover().expect("paths");
        let config = Config::for_testing_with_repos(PathBuf::from("."), paths, Vec::new());
        let target = Platform::new("macos", "aarch64").unwrap();

        let ctx = build_activation_context(None, &config, Some(&target));

        assert_eq!(ctx.os_name.as_deref(), Some("mac os x"));
        assert_eq!(ctx.os_arch.as_deref(), Some("aarch64"));
        assert_eq!(ctx.os_family.as_deref(), Some("mac"));
        assert_eq!(
            ctx.properties.get("os.name").map(String::as_str),
            Some("mac os x")
        );
        assert_eq!(
            ctx.properties.get("os.arch").map(String::as_str),
            Some("aarch64")
        );
        assert_eq!(
            ctx.properties.get("os.family").map(String::as_str),
            Some("mac")
        );
    }

    /// A Windows target on any host maps to os.name "windows", family "windows".
    #[test]
    fn build_activation_context_target_windows() {
        let paths = ResolvedPaths::discover().expect("paths");
        let config = Config::for_testing_with_repos(PathBuf::from("."), paths, Vec::new());
        let target = Platform::new("windows", "x86_64").unwrap();

        let ctx = build_activation_context(None, &config, Some(&target));

        assert_eq!(ctx.os_name.as_deref(), Some("windows"));
        assert_eq!(ctx.os_arch.as_deref(), Some("x86_64"));
        assert_eq!(ctx.os_family.as_deref(), Some("windows"));
    }

    #[test]
    fn load_local_parent_handles_directory_path() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let base_dir = tmp_dir.path().to_path_buf();
        let subdir = base_dir.join("subdir");
        std::fs::create_dir(&subdir).unwrap();
        std::fs::write(subdir.join("pom.xml"), pom_xml("parent")).unwrap();

        let resolver = ParentResolverBase::new(Some(base_dir), MockFetcher, false);
        let parent = Parent {
            group_id: "com.example".to_string(),
            artifact_id: "parent".to_string(),
            version: "1.0.0".to_string(),
            relative_path: Some("subdir".to_string()),
        };

        let pom = resolver.load_local_parent(&parent).expect("resolved");
        assert_eq!(pom.artifact_id.as_deref(), Some("parent"));
    }

    #[test]
    fn load_local_parent_handles_dot_dot_relative_path() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let parent_dir = tmp_dir.path().join("parent");
        let child_dir = parent_dir.join("child");
        std::fs::create_dir_all(&child_dir).unwrap();
        std::fs::write(parent_dir.join("pom.xml"), pom_xml("root")).unwrap();

        // `project_root` must be set to the repository/workspace root so that
        // legitimate `../` navigation within the project is allowed. When
        // `ParentResolverBase::new` is called with `base_dir = child_dir`, the
        // default `project_root` is also `child_dir`, which would reject a
        // `../` relative path pointing to the parent module. In production the
        // resolver sets `project_root` to the top-level workspace root.
        let mut resolver = ParentResolverBase::new(Some(child_dir), MockFetcher, false);
        resolver.project_root = Some(tmp_dir.path().to_path_buf());
        let parent = Parent {
            group_id: "com.example".to_string(),
            artifact_id: "root".to_string(),
            version: "1.0.0".to_string(),
            relative_path: Some("../".to_string()),
        };

        let pom = resolver.load_local_parent(&parent).expect("resolved");
        assert_eq!(pom.artifact_id.as_deref(), Some("root"));
    }

    /// Security: a hostile `<relativePath>` that escapes the project root must
    /// be silently rejected (falls through to remote resolution, returns `None`).
    /// Without this guard the containment check never fires because `project_root`
    /// was `None`, leaving the resolver open to arbitrary local file reads.
    #[test]
    fn load_local_parent_rejects_path_escaping_project_root() {
        let tmp_dir = tempfile::tempdir().unwrap();
        // project_root is the workspace root; the POM lives inside it.
        let project_root = tmp_dir.path().join("project");
        let module_dir = project_root.join("module");
        std::fs::create_dir_all(&module_dir).unwrap();

        // Place a POM *outside* the project root so we can verify it is not read.
        let outside_dir = tmp_dir.path().join("outside");
        std::fs::create_dir_all(&outside_dir).unwrap();
        std::fs::write(outside_dir.join("pom.xml"), pom_xml("evil")).unwrap();

        let resolver = ParentResolverBase::new(Some(module_dir), MockFetcher, false);
        // project_root is already set to module_dir by ::new; update it to the
        // workspace root so intra-project navigation would pass but the
        // crafted path below still escapes.
        // (No update needed here: module_dir IS project_root, so any `../../`
        //  navigation that leaves it is rejected.)
        let parent = Parent {
            group_id: "com.example".to_string(),
            artifact_id: "evil".to_string(),
            version: "1.0.0".to_string(),
            // Navigate from module_dir → project_root → tmp_dir/outside
            relative_path: Some("../../outside".to_string()),
        };

        let result = resolver.load_local_parent(&parent);
        assert!(
            result.is_none(),
            "hostile relativePath escaping project root must be rejected, not resolved to Some"
        );
    }

    #[test]
    fn parse_maven_config_extracts_properties() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let mvn_dir = tmp_dir.path().join(".mvn");
        std::fs::create_dir(&mvn_dir).unwrap();
        std::fs::write(
            mvn_dir.join("maven.config"),
            "-Drevision=2.17.0\n-Dchangelist=-SNAPSHOT\n-Dsha1=\n",
        )
        .unwrap();

        let props = parse_maven_config(tmp_dir.path());
        assert_eq!(props.get("revision").map(String::as_str), Some("2.17.0"));
        assert_eq!(
            props.get("changelist").map(String::as_str),
            Some("-SNAPSHOT")
        );
        assert_eq!(props.get("sha1").map(String::as_str), Some(""));
    }

    #[test]
    fn parse_maven_config_handles_missing_file() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let props = parse_maven_config(tmp_dir.path());
        assert!(props.is_empty());
    }

    #[test]
    fn parse_maven_config_handles_single_line_format() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let mvn_dir = tmp_dir.path().join(".mvn");
        std::fs::create_dir(&mvn_dir).unwrap();
        std::fs::write(
            mvn_dir.join("maven.config"),
            "-Drevision=1.0.0 -Dchangelist= -Dflag",
        )
        .unwrap();

        let props = parse_maven_config(tmp_dir.path());
        assert_eq!(props.get("revision").map(String::as_str), Some("1.0.0"));
        assert_eq!(props.get("changelist").map(String::as_str), Some(""));
        assert_eq!(props.get("flag").map(String::as_str), Some("true"));
    }
}
