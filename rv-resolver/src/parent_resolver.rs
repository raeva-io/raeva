//! Parent POM resolution: local `<relativePath>`, remote fetch with the
//! missing-parent cache, and activation-context construction.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rv_config::{Config, ConfigError, Platform};
use rv_maven_model::{
    ActivationContext, MAX_PARENT_CHAIN_DEPTH, Parent, Pom, PomError, interpolate_parent,
    interpolate_parent_with_user_properties,
};
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

/// One accepted hop of a local parent chain: where the parent POM was read
/// from, and its parsed model.
struct LocalParentHop {
    path: PathBuf,
    pom: Pom,
}

/// The single gate every local `<relativePath>` parent passes through.
///
/// `None` means the hop is not an accepted local parent and the caller falls
/// back to repository resolution: the relativePath is the empty "skip local
/// lookup" sentinel, it escapes `boundary` after symlink-aware
/// canonicalization, the file is absent, unreadable, larger than
/// [`rv_config::MAX_PROJECT_INPUT_SIZE`], or unparseable, or the POM found
/// there does not carry the declared parent coordinates. An oversize file is a
/// rejected parent rather than a hard error, so resolution and the hash
/// traversal agree on it exactly as they do on an escaping or mismatched one.
fn accept_local_parent(
    base_dir: &Path,
    boundary: Option<&Path>,
    parent: &Parent,
) -> Option<LocalParentHop> {
    let relative = match parent.relative_path.as_deref() {
        Some("") => return None,
        Some(path) => path,
        None => "../pom.xml",
    };
    let mut path = base_dir.join(relative);

    // Reject `<relativePath>` values that escape the project tree (e.g.
    // `<relativePath>../../../../etc/passwd</relativePath>`); fall through
    // to remote resolution.
    if let Some(root) = boundary
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

    let pom = match rv_config::read_project_input_string(&path) {
        Ok(contents) => read_and_validate_pom(&path, &contents, parent, false)?,
        Err(e) if io_error_kind(&e) == Some(std::io::ErrorKind::IsADirectory) => {
            // Pre-check missed a directory (TOCTOU); retry with pom.xml appended.
            path.push("pom.xml");
            let contents = rv_config::read_project_input_string(&path).ok()?;
            read_and_validate_pom(&path, &contents, parent, true)?
        }
        Err(e) => {
            if io_error_kind(&e) != Some(std::io::ErrorKind::NotFound) {
                tracing::warn!(
                    "Failed to read local parent POM at {}: {}",
                    path.display(),
                    e
                );
            }
            return None;
        }
    };
    Some(LocalParentHop { path, pom })
}

/// Underlying `io::ErrorKind` of a bounded-read failure, if it was an I/O
/// error at all; oversize and encoding failures carry none.
fn io_error_kind(error: &ConfigError) -> Option<std::io::ErrorKind> {
    match error {
        ConfigError::ProjectInputIo { source, .. } => Some(source.kind()),
        _ => None,
    }
}

fn load_local_parent_at(
    base_dir: Option<&Path>,
    project_root: Option<&Path>,
    parent: &Parent,
) -> Option<Pom> {
    accept_local_parent(base_dir?, project_root, parent).map(|hop| hop.pom)
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

/// The directory a local `<relativePath>` parent must stay inside, for a
/// reactor rooted at `root` with `module_count` active modules.
///
/// A discovered reactor is its own containment boundary. A one-module
/// workspace can also be a deliberately selected submodule (for example
/// `guava/guava`) whose Maven parent is the immediate `../pom.xml`, so exactly
/// one directory level above the root is admitted; deeper escapes such as
/// `../../etc/passwd` stay rejected. Multi-module roots already contain their
/// local parents, so they keep the tighter boundary.
///
/// Reactor discovery, `rv sync`'s model hashing, and resolution all derive
/// their boundary here, so all three accept exactly the same set of local
/// parents.
pub fn local_parent_boundary(root: &Path, module_count: usize) -> PathBuf {
    if module_count == 1 {
        root.parent().unwrap_or(root).to_path_buf()
    } else {
        root.to_path_buf()
    }
}

/// Walk the chain of local parent POMs reachable from `pom_path` (whose bytes
/// are `pom_xml`) via `<parent><relativePath>`, in child-to-ancestor order.
///
/// This is the one accepted-local-parent traversal: a hop is yielded only when
/// resolution itself would load that file as the parent, i.e. it stays inside
/// `boundary` after symlink-aware canonicalization, exists, is within the
/// project input size limit, parses, and declares the coordinates the child
/// asked for — the coordinates [`interpolate_parent`] derives from the
/// declaration, so a `${revision}` parent version names the same POM here as it
/// does during inheritance. The walk stops at the first hop that fails any of
/// those, and at a cycle.
///
/// Depth is bounded by [`MAX_PARENT_CHAIN_DEPTH`], the same limit inheritance
/// resolution applies: a chain within the limit is reported in full, and a
/// chain that needs one more hop is rejected by inheritance itself, so no
/// resolution result can depend on a parent this walk did not report.
///
/// `user_properties` are the reactor root's `.mvn/maven.config` `-D` entries
/// (see [`parse_maven_config`]), which resolution overlays on the POM it
/// starts from before inheritance runs. They therefore apply to this walk's
/// first hop and to no other: an ancestor is loaded from disk with its own
/// properties alone, exactly as resolution loads it. Pass an empty map only
/// where resolution has no user properties either.
///
/// Callers derive `boundary` from [`local_parent_boundary`] (or
/// [`Workspace::local_parent_boundary`](crate::Workspace::local_parent_boundary)).
pub fn accepted_local_parents(
    pom_path: &Path,
    pom_xml: &str,
    boundary: &Path,
    user_properties: &HashMap<String, String>,
) -> Vec<PathBuf> {
    let mut chain = Vec::new();
    let Ok(mut pom) = Pom::parse(pom_xml) else {
        return chain;
    };
    let mut seen: HashSet<PathBuf> = HashSet::new();
    seen.insert(canonical_or_owned(pom_path));
    let mut base_dir = pom_path.parent().unwrap_or(Path::new(".")).to_path_buf();

    for depth in 0..MAX_PARENT_CHAIN_DEPTH {
        let Some(raw_parent) = pom.parent.as_ref() else {
            break;
        };
        // The declaration is not the parent's identity: `${revision}`-style
        // coordinates name a different POM once expanded. Inheritance expands
        // them with the declaring POM's own properties before it resolves the
        // hop, so the walk must too, or a parent that resolution loads goes
        // unhashed. The starting POM additionally carries the user properties
        // resolution injected into it, so a parent version supplied only by
        // `.mvn/maven.config` names the same POM here as it does there.
        // An interpolation failure ends the walk: inheritance surfaces the same
        // failure as an error, so no resolution result survives it.
        let interpolated = if depth == 0 {
            interpolate_parent_with_user_properties(&pom.properties, user_properties, raw_parent)
        } else {
            interpolate_parent(&pom.properties, raw_parent)
        };
        let Ok(parent) = interpolated else {
            break;
        };
        let Some(hop) = accept_local_parent(&base_dir, Some(boundary), &parent) else {
            break;
        };
        if !seen.insert(canonical_or_owned(&hop.path)) {
            break;
        }
        base_dir = hop.path.parent().unwrap_or(Path::new(".")).to_path_buf();
        chain.push(hop.path);
        pom = hop.pom;
    }

    chain
}

fn canonical_or_owned(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
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
///
/// These are Maven user properties: resolution overlays them on the POM it
/// starts from, so any traversal that has to name the same parents
/// ([`accepted_local_parents`]) needs them too.
pub fn parse_maven_config(project_root: &Path) -> HashMap<String, String> {
    let config_path = project_root.join(".mvn").join("maven.config");
    let content = match rv_config::read_optional_project_input_string(&config_path) {
        Ok(Some(content)) => content,
        Ok(None) => return HashMap::new(),
        Err(err) => {
            // Oversize and unreadable configs are ignored with a warning, the
            // same as any other read failure here: this helper has no error
            // channel and its callers build an activation context regardless.
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
    let content = match read_optional_project_input_string_async(&config_path).await {
        Ok(Some(content)) => content,
        Ok(None) => return HashMap::new(),
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

/// Async mirror of [`rv_config::read_optional_project_input_string`]: `Ok(None)`
/// when the file is absent, and the same bounded read otherwise so an oversize
/// file cannot drive an unbounded allocation.
async fn read_optional_project_input_string_async(
    path: &Path,
) -> Result<Option<String>, ConfigError> {
    match read_project_input_string_async(path).await {
        Ok(contents) => Ok(Some(contents)),
        Err(ConfigError::ProjectInputIo { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

/// Async mirror of [`rv_config::read_project_input_string`]: the same
/// [`rv_config::MAX_PROJECT_INPUT_SIZE`] bound, applied without blocking the
/// executor, so an oversize project input cannot drive an unbounded allocation
/// on an async path.
pub(crate) async fn read_project_input_string_async(path: &Path) -> Result<String, ConfigError> {
    use tokio::io::AsyncReadExt;

    let file = tokio::fs::File::open(path)
        .await
        .map_err(|source| ConfigError::ProjectInputIo {
            path: path.to_path_buf(),
            source,
        })?;

    let mut bytes = Vec::new();
    file.take(rv_config::MAX_PROJECT_INPUT_SIZE as u64 + 1)
        .read_to_end(&mut bytes)
        .await
        .map_err(|source| ConfigError::ProjectInputIo {
            path: path.to_path_buf(),
            source,
        })?;
    if bytes.len() > rv_config::MAX_PROJECT_INPUT_SIZE {
        return Err(ConfigError::ProjectInputTooLarge {
            path: path.to_path_buf(),
            limit: rv_config::MAX_PROJECT_INPUT_SIZE,
        });
    }

    String::from_utf8(bytes).map_err(|_| ConfigError::ProjectInputEncoding {
        path: path.to_path_buf(),
    })
}

fn parse_maven_config_content(content: &str) -> HashMap<String, String> {
    let mut properties = HashMap::new();
    let tokens: Vec<&str> = content.split_whitespace().collect();
    let mut index = 0;
    while index < tokens.len() {
        let token = tokens[index];
        let property = if token == "-D" {
            index += 1;
            tokens.get(index).copied()
        } else {
            token.strip_prefix("-D")
        };
        if let Some(property) = property.filter(|property| !property.is_empty()) {
            let (key, value) = property.split_once('=').unwrap_or((property, "true"));
            if !key.is_empty() {
                properties.insert(key.to_string(), value.to_string());
            }
        }
        index += 1;
    }
    if !properties.is_empty() {
        tracing::debug!(
            count = properties.len(),
            "Loaded properties from .mvn/maven.config"
        );
    }
    properties
}

/// Build the effective Maven activation context for a reactor discovery or
/// model resolution targeting `target_platform`.
///
/// This is public so the CLI can rediscover a reactor for `--frozen` without
/// performing repository resolution while still using exactly the same
/// profile/property/platform inputs as the resolver.
pub fn build_activation_context(
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
    use rv_maven_model::EffectiveDescriptor;

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

    /// Child POM referencing `parent` by coordinates and `relative_path`.
    fn child_xml(artifact_id: &str, parent_artifact_id: &str, relative_path: &str) -> String {
        format!(
            r#"<project>
                <modelVersion>4.0.0</modelVersion>
                <parent>
                    <groupId>com.example</groupId>
                    <artifactId>{parent_artifact_id}</artifactId>
                    <version>1.0.0</version>
                    <relativePath>{relative_path}</relativePath>
                </parent>
                <artifactId>{artifact_id}</artifactId>
            </project>"#
        )
    }

    /// POM at an explicit version, carrying a raw `<properties>` block.
    fn versioned_pom_xml(artifact_id: &str, version: &str, properties: &str) -> String {
        format!(
            r#"<project>
                <modelVersion>4.0.0</modelVersion>
                <groupId>com.example</groupId>
                <artifactId>{artifact_id}</artifactId>
                <version>{version}</version>
                <packaging>pom</packaging>
                {properties}
            </project>"#
        )
    }

    /// Child POM carrying a raw `<properties>` block, declaring its parent at
    /// `parent_version` (which may be a `${{...}}` reference) and itself at
    /// `version`.
    fn child_xml_with_properties(
        artifact_id: &str,
        version: &str,
        properties: &str,
        parent_artifact_id: &str,
        parent_version: &str,
        relative_path: &str,
    ) -> String {
        format!(
            r#"<project>
                <modelVersion>4.0.0</modelVersion>
                {properties}
                <parent>
                    <groupId>com.example</groupId>
                    <artifactId>{parent_artifact_id}</artifactId>
                    <version>{parent_version}</version>
                    <relativePath>{relative_path}</relativePath>
                </parent>
                <artifactId>{artifact_id}</artifactId>
                <version>{version}</version>
            </project>"#
        )
    }

    /// Walk a chain the way a project without `.mvn/maven.config` is walked.
    /// The user-property layering has its own tests below.
    fn walk_parents(pom_path: &Path, pom_xml: &str, boundary: &Path) -> Vec<PathBuf> {
        accepted_local_parents(pom_path, pom_xml, boundary, &HashMap::new())
    }

    fn user_properties(entries: &[(&str, &str)]) -> HashMap<String, String> {
        entries
            .iter()
            .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
            .collect()
    }

    #[test]
    fn accepted_local_parents_walks_the_whole_chain() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let root = tmp_dir.path();
        let child_dir = root.join("a").join("b");
        std::fs::create_dir_all(&child_dir).unwrap();
        std::fs::write(root.join("pom.xml"), pom_xml("grandparent")).unwrap();
        std::fs::write(
            root.join("a").join("pom.xml"),
            child_xml("parent", "grandparent", "../pom.xml"),
        )
        .unwrap();
        let child_pom = child_dir.join("pom.xml");
        let xml = child_xml("child", "parent", "../pom.xml");
        std::fs::write(&child_pom, &xml).unwrap();

        let chain = walk_parents(&child_pom, &xml, root);

        let chain: Vec<PathBuf> = chain.iter().map(|path| canonical_or_owned(path)).collect();
        assert_eq!(
            chain,
            [
                canonical_or_owned(&root.join("a").join("pom.xml")),
                canonical_or_owned(&root.join("pom.xml")),
            ]
        );
    }

    /// Security: the walker must not read (or report) a file outside the
    /// boundary, which is what put an arbitrary local path and digest into the
    /// commit-bound lockfile's model hash.
    #[test]
    fn accepted_local_parents_rejects_escape_outside_boundary() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let boundary = tmp_dir.path().join("project");
        let module_dir = boundary.join("module");
        std::fs::create_dir_all(&module_dir).unwrap();
        let outside = tmp_dir.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("pom.xml"), pom_xml("evil")).unwrap();

        let pom_path = module_dir.join("pom.xml");
        let xml = child_xml("child", "evil", "../../outside/pom.xml");
        std::fs::write(&pom_path, &xml).unwrap();

        assert!(walk_parents(&pom_path, &xml, &boundary).is_empty());
    }

    /// The containment check canonicalizes, so a symlink that points out of
    /// the boundary is rejected even though the literal path stays inside.
    #[cfg(unix)]
    #[test]
    fn accepted_local_parents_rejects_symlink_escape() {
        use std::os::unix::fs::symlink;

        let tmp_dir = tempfile::tempdir().unwrap();
        let boundary = tmp_dir.path().join("project");
        std::fs::create_dir_all(&boundary).unwrap();
        let outside = tmp_dir.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("pom.xml"), pom_xml("evil")).unwrap();
        symlink(&outside, boundary.join("escape")).unwrap();

        let pom_path = boundary.join("pom.xml");
        let xml = child_xml("child", "evil", "escape/pom.xml");
        std::fs::write(&pom_path, &xml).unwrap();

        assert!(walk_parents(&pom_path, &xml, &boundary).is_empty());
    }

    /// A contained file that is not the declared parent is not a parent, so it
    /// is neither loaded by resolution nor reported by the walker.
    #[test]
    fn accepted_local_parents_rejects_declared_gav_mismatch() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let root = tmp_dir.path();
        std::fs::write(root.join("pom.xml"), pom_xml("actual-parent")).unwrap();
        let module_dir = root.join("module");
        std::fs::create_dir_all(&module_dir).unwrap();
        let pom_path = module_dir.join("pom.xml");
        let xml = child_xml("child", "declared-parent", "../pom.xml");
        std::fs::write(&pom_path, &xml).unwrap();

        assert!(walk_parents(&pom_path, &xml, root).is_empty());
    }

    /// The CI-friendly `<revision>` pattern: the parent version is a property,
    /// so the raw declaration matches nothing. Resolution interpolates it and
    /// loads the local parent, so the walk must report that same file — the
    /// divergence this guards let an edit to a resolved parent slip past the
    /// model hash.
    #[test]
    fn accepted_local_parents_interpolates_a_property_parent_version() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let root = tmp_dir.path();
        let parent_pom = root.join("pom.xml");
        std::fs::write(
            &parent_pom,
            versioned_pom_xml(
                "parent",
                "2.0.0",
                "<properties><localrev>7.7.7</localrev></properties>",
            ),
        )
        .unwrap();
        let module_dir = root.join("module");
        std::fs::create_dir_all(&module_dir).unwrap();
        let pom_path = module_dir.join("pom.xml");
        let xml = child_xml_with_properties(
            "child",
            "${localrev}",
            "<properties><revision>2.0.0</revision></properties>",
            "parent",
            "${revision}",
            "../pom.xml",
        );
        std::fs::write(&pom_path, &xml).unwrap();

        let chain = walk_parents(&pom_path, &xml, root);
        assert_eq!(
            chain
                .iter()
                .map(|path| canonical_or_owned(path))
                .collect::<Vec<_>>(),
            [canonical_or_owned(&parent_pom)],
            "the parent resolution loads must be hashed"
        );

        // `localrev` is declared only by the local parent, so an effective
        // version of 7.7.7 proves resolution read that same file.
        let descriptor = resolve_with_local_parents(root, &pom_path, &xml).expect("resolves");
        assert_eq!(descriptor.gav.version, "7.7.7");
    }

    /// A parent version supplied only by `.mvn/maven.config`. Resolution
    /// overlays those `-D` entries on the POM before inheritance, so it loads
    /// the local parent; the walk must layer the same entries or the parent
    /// that shapes the resolved graph is never hashed and an edit to it slips
    /// past `--frozen` and the fast path.
    #[test]
    fn accepted_local_parents_layers_user_properties_on_the_starting_pom() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let root = tmp_dir.path();
        let parent_pom = root.join("pom.xml");
        std::fs::write(
            &parent_pom,
            versioned_pom_xml(
                "parent",
                "1.2.3",
                "<properties><localrev>7.7.7</localrev></properties>",
            ),
        )
        .unwrap();
        let module_dir = root.join("module");
        std::fs::create_dir_all(&module_dir).unwrap();
        let pom_path = module_dir.join("pom.xml");
        // No `<properties>` of its own: only `-DparentVersion=1.2.3` can name
        // this parent.
        let xml = child_xml_with_properties(
            "child",
            "${localrev}",
            "",
            "parent",
            "${parentVersion}",
            "../pom.xml",
        );
        std::fs::write(&pom_path, &xml).unwrap();
        let properties = user_properties(&[("parentVersion", "1.2.3")]);

        assert_eq!(
            accepted_local_parents(&pom_path, &xml, root, &properties)
                .iter()
                .map(|path| canonical_or_owned(path))
                .collect::<Vec<_>>(),
            [canonical_or_owned(&parent_pom)],
            "the parent resolution loads must be hashed"
        );
        assert_eq!(
            resolve_with_user_properties(root, &pom_path, &xml, &properties)
                .expect("resolves")
                .gav
                .version,
            "7.7.7",
            "`localrev` comes only from the parent, so resolution read that file"
        );

        // Without the user properties neither side can name the parent, which
        // is what made the two agree before: the walk reports nothing and
        // inheritance cannot even parse the unexpanded version as a coordinate.
        assert!(walk_parents(&pom_path, &xml, root).is_empty());
        assert!(resolve_with_local_parents(root, &pom_path, &xml).is_err());
    }

    /// Maven user properties sit above POM `<properties>`, so a `-D` entry
    /// wins over a same-named declaration in the POM and can retarget the
    /// parent hop. The walk applies that precedence exactly as the model layer
    /// does.
    #[test]
    fn accepted_local_parents_lets_user_properties_override_pom_properties() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let root = tmp_dir.path();
        let parent_pom = root.join("pom.xml");
        std::fs::write(
            &parent_pom,
            versioned_pom_xml(
                "parent",
                "2.0.0",
                "<properties><localrev>7.7.7</localrev></properties>",
            ),
        )
        .unwrap();
        let module_dir = root.join("module");
        std::fs::create_dir_all(&module_dir).unwrap();
        let pom_path = module_dir.join("pom.xml");
        let xml = child_xml_with_properties(
            "child",
            "${localrev}",
            "<properties><revision>1.0.0</revision></properties>",
            "parent",
            "${revision}",
            "../pom.xml",
        );
        std::fs::write(&pom_path, &xml).unwrap();

        // The POM's own `revision` names a parent version that is not on disk.
        assert!(walk_parents(&pom_path, &xml, root).is_empty());

        let properties = user_properties(&[("revision", "2.0.0")]);
        assert_eq!(
            accepted_local_parents(&pom_path, &xml, root, &properties)
                .iter()
                .map(|path| canonical_or_owned(path))
                .collect::<Vec<_>>(),
            [canonical_or_owned(&parent_pom)],
            "the `-D` entry outranks the POM property, here and in resolution"
        );
        assert_eq!(
            resolve_with_user_properties(root, &pom_path, &xml, &properties)
                .expect("resolves")
                .gav
                .version,
            "7.7.7"
        );
    }

    /// User properties reach the POM the walk starts from and no other:
    /// resolution overlays them on the model it builds, then loads every
    /// ancestor from disk with that ancestor's own properties alone.
    #[test]
    fn accepted_local_parents_does_not_layer_user_properties_on_ancestors() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let root = tmp_dir.path();
        let top_dir = root.join("top");
        let mid_dir = root.join("mid");
        let child_dir = root.join("child");
        for dir in [&top_dir, &mid_dir, &child_dir] {
            std::fs::create_dir_all(dir).unwrap();
        }

        std::fs::write(
            top_dir.join("pom.xml"),
            versioned_pom_xml("top", "3.0.0", ""),
        )
        .unwrap();
        let mid_pom = mid_dir.join("pom.xml");
        // `topVersion` is declared nowhere in `mid`, so this hop names nothing
        // whatever the user properties say.
        std::fs::write(
            &mid_pom,
            child_xml_with_properties("mid", "2.0.0", "", "top", "${topVersion}", "../top/pom.xml"),
        )
        .unwrap();
        let child_pom = child_dir.join("pom.xml");
        let xml = child_xml_with_properties(
            "child",
            "1.0.0",
            "",
            "mid",
            "${midVersion}",
            "../mid/pom.xml",
        );
        std::fs::write(&child_pom, &xml).unwrap();

        let properties = user_properties(&[("midVersion", "2.0.0"), ("topVersion", "3.0.0")]);
        let chain = accepted_local_parents(&child_pom, &xml, root, &properties);
        assert_eq!(
            chain
                .iter()
                .map(|path| canonical_or_owned(path))
                .collect::<Vec<_>>(),
            [canonical_or_owned(&mid_pom)],
            "the walk stops where inheritance stops: `mid` cannot expand its own parent version"
        );
        assert!(
            resolve_with_user_properties(root, &child_pom, &xml, &properties).is_err(),
            "inheritance fails on `mid`'s unexpanded parent version, so no \
             resolution result depends on `top`"
        );
    }

    /// Every hop interpolates its own `<parent>` with its own `<properties>`,
    /// exactly as inheritance does: `revision` means 2.0.0 in the child and
    /// 3.0.0 in the intermediate parent, and each hop resolves against the one
    /// its own POM declares.
    #[test]
    fn accepted_local_parents_interpolates_each_hop_with_its_own_properties() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let root = tmp_dir.path();
        let top_dir = root.join("top");
        let mid_dir = root.join("mid");
        let child_dir = root.join("child");
        for dir in [&top_dir, &mid_dir, &child_dir] {
            std::fs::create_dir_all(dir).unwrap();
        }

        let top_pom = top_dir.join("pom.xml");
        std::fs::write(
            &top_pom,
            versioned_pom_xml(
                "top",
                "3.0.0",
                "<properties><localrev>7.7.7</localrev></properties>",
            ),
        )
        .unwrap();
        let mid_pom = mid_dir.join("pom.xml");
        std::fs::write(
            &mid_pom,
            child_xml_with_properties(
                "mid",
                "2.0.0",
                "<properties><revision>3.0.0</revision></properties>",
                "top",
                "${revision}",
                "../top/pom.xml",
            ),
        )
        .unwrap();
        let child_pom = child_dir.join("pom.xml");
        let xml = child_xml_with_properties(
            "child",
            "${localrev}",
            "<properties><revision>2.0.0</revision></properties>",
            "mid",
            "${revision}",
            "../mid/pom.xml",
        );
        std::fs::write(&child_pom, &xml).unwrap();

        let chain = walk_parents(&child_pom, &xml, root);
        assert_eq!(
            chain
                .iter()
                .map(|path| canonical_or_owned(path))
                .collect::<Vec<_>>(),
            [canonical_or_owned(&mid_pom), canonical_or_owned(&top_pom)],
            "each hop must expand its own ${{revision}}"
        );

        // Only the top of the chain declares `localrev`.
        let descriptor = resolve_with_local_parents(root, &child_pom, &xml).expect("resolves");
        assert_eq!(descriptor.gav.version, "7.7.7");
    }

    /// Properties flow parent-to-child only after the chain is walked, so a
    /// property a parent declares cannot name that parent's own parent.
    /// Inheritance leaves such a reference literal and stops resolving the
    /// chain there; the walk must stop at the same hop rather than hash an
    /// ancestor resolution never reads.
    #[test]
    fn parent_properties_do_not_reach_their_own_parent_coordinates() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let root = tmp_dir.path();
        let top_dir = root.join("top");
        let mid_dir = root.join("mid");
        let child_dir = root.join("child");
        for dir in [&top_dir, &mid_dir, &child_dir] {
            std::fs::create_dir_all(dir).unwrap();
        }

        // `toprev` is declared by the top POM, which is exactly the POM the
        // intermediate parent tries to name with it.
        std::fs::write(
            top_dir.join("pom.xml"),
            versioned_pom_xml(
                "top",
                "3.0.0",
                "<properties><toprev>3.0.0</toprev></properties>",
            ),
        )
        .unwrap();
        let mid_pom = mid_dir.join("pom.xml");
        std::fs::write(
            &mid_pom,
            child_xml_with_properties("mid", "2.0.0", "", "top", "${toprev}", "../top/pom.xml"),
        )
        .unwrap();
        let child_pom = child_dir.join("pom.xml");
        let xml = child_xml_with_properties("child", "1.0.0", "", "mid", "2.0.0", "../mid/pom.xml");
        std::fs::write(&child_pom, &xml).unwrap();

        let chain = walk_parents(&child_pom, &xml, root);
        assert_eq!(
            chain
                .iter()
                .map(|path| canonical_or_owned(path))
                .collect::<Vec<_>>(),
            [canonical_or_owned(&mid_pom)],
            "the unresolvable hop and everything past it stays out of the hash"
        );
    }

    /// Interpolation is not a free pass: coordinates that still disagree once
    /// expanded are a rejected parent for the walk and for resolution alike.
    #[test]
    fn accepted_local_parents_rejects_interpolated_gav_mismatch() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let root = tmp_dir.path();
        std::fs::write(root.join("pom.xml"), pom_xml("parent")).unwrap();
        let module_dir = root.join("module");
        std::fs::create_dir_all(&module_dir).unwrap();
        let pom_path = module_dir.join("pom.xml");
        // `parent` is at 1.0.0; ${revision} expands to a version it never had.
        let xml = child_xml_with_properties(
            "child",
            "9.9.9",
            "<properties><revision>9.9.9</revision></properties>",
            "parent",
            "${revision}",
            "../pom.xml",
        );
        std::fs::write(&pom_path, &xml).unwrap();

        assert!(walk_parents(&pom_path, &xml, root).is_empty());

        let mut resolver = ParentResolverBase::new(Some(module_dir), MockFetcher, false);
        resolver.project_root = Some(root.to_path_buf());
        let parent = Parent {
            group_id: "com.example".to_string(),
            artifact_id: "parent".to_string(),
            version: "9.9.9".to_string(),
            relative_path: Some("../pom.xml".to_string()),
        };
        assert!(resolver.load_local_parent(&parent).is_none());
    }

    /// Local parent chain `root/p1 -> root/p2 -> ... -> root/p{length}`, with a
    /// leaf at `root/child/pom.xml` whose parent is `p1`. Returns the leaf POM
    /// path and its XML.
    fn write_local_parent_chain(root: &Path, length: usize) -> (PathBuf, String) {
        for index in 1..=length {
            let dir = root.join(format!("p{index}"));
            std::fs::create_dir_all(&dir).unwrap();
            let xml = if index < length {
                child_xml(
                    &format!("p{index}"),
                    &format!("p{}", index + 1),
                    &format!("../p{}/pom.xml", index + 1),
                )
            } else {
                pom_xml(&format!("p{index}"))
            };
            std::fs::write(dir.join("pom.xml"), xml).unwrap();
        }

        let child_dir = root.join("child");
        std::fs::create_dir_all(&child_dir).unwrap();
        let xml = child_xml("child", "p1", "../p1/pom.xml");
        let child_pom = child_dir.join("pom.xml");
        std::fs::write(&child_pom, &xml).unwrap();
        (child_pom, xml)
    }

    /// Resolves parents from the local chain only; remote lookups return
    /// `None`, as they do for a reactor rooted in a tempdir.
    struct LocalOnlyResolver {
        base: ParentResolverBase<MockFetcher>,
    }

    impl rv_maven_model::ParentResolver for LocalOnlyResolver {
        fn resolve_parent(&self, parent: &Parent) -> Result<Option<Pom>, PomError> {
            self.base.resolve_parent(parent)
        }

        fn strict_parent_resolution(&self) -> bool {
            false
        }
    }

    fn resolve_with_local_parents(
        root: &Path,
        child_pom: &Path,
        xml: &str,
    ) -> Result<EffectiveDescriptor, PomError> {
        let mut base = ParentResolverBase::new(
            child_pom.parent().map(Path::to_path_buf),
            MockFetcher,
            false,
        );
        base.project_root = Some(root.to_path_buf());
        Pom::parse(xml)?.effective_descriptor_with_inheritance(
            LocalOnlyResolver { base },
            &ActivationContext::default(),
        )
    }

    /// [`resolve_with_local_parents`] with `.mvn/maven.config` in play: the
    /// `-D` entries are overlaid on the starting POM before inheritance, which
    /// is what `Resolver::load_root_project` and workspace module resolution
    /// do with the reactor root's config.
    fn resolve_with_user_properties(
        root: &Path,
        child_pom: &Path,
        xml: &str,
        user_properties: &HashMap<String, String>,
    ) -> Result<EffectiveDescriptor, PomError> {
        let mut base = ParentResolverBase::new(
            child_pom.parent().map(Path::to_path_buf),
            MockFetcher,
            false,
        );
        base.project_root = Some(root.to_path_buf());
        let mut pom = Pom::parse(xml)?;
        for (key, value) in user_properties {
            pom.properties.insert(key.as_str(), value.as_str());
        }
        pom.effective_descriptor_with_inheritance(
            LocalOnlyResolver { base },
            &ActivationContext::default(),
        )
    }

    /// A chain at the shared limit is reported in full, so editing its deepest
    /// parent changes the model hash, and resolution accepts exactly the same
    /// parents.
    #[test]
    fn accepted_local_parents_covers_a_chain_at_the_depth_limit() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let root = tmp_dir.path();
        let (child_pom, xml) = write_local_parent_chain(root, MAX_PARENT_CHAIN_DEPTH);

        let chain = walk_parents(&child_pom, &xml, root);

        assert_eq!(chain.len(), MAX_PARENT_CHAIN_DEPTH);
        assert_eq!(
            canonical_or_owned(chain.last().unwrap()),
            canonical_or_owned(
                &root
                    .join(format!("p{MAX_PARENT_CHAIN_DEPTH}"))
                    .join("pom.xml")
            ),
            "the deepest parent resolution reads must be hashed"
        );
        resolve_with_local_parents(root, &child_pom, &xml).expect("a chain at the limit resolves");
    }

    /// The divergence this guards: a parent past the shared limit must not
    /// participate in resolution while sitting outside the model hash. The walk
    /// stops at the limit, and resolution rejects the chain outright, so
    /// editing the unhashed deepest parent cannot change a successful
    /// resolution.
    #[test]
    fn depth_limit_rejects_a_chain_past_the_limit_on_both_paths() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let root = tmp_dir.path();
        let (child_pom, xml) = write_local_parent_chain(root, MAX_PARENT_CHAIN_DEPTH + 1);

        let chain = walk_parents(&child_pom, &xml, root);
        assert_eq!(chain.len(), MAX_PARENT_CHAIN_DEPTH);
        let deepest = canonical_or_owned(
            &root
                .join(format!("p{}", MAX_PARENT_CHAIN_DEPTH + 1))
                .join("pom.xml"),
        );
        assert!(
            !chain.iter().any(|path| canonical_or_owned(path) == deepest),
            "the over-limit parent must not be hashed"
        );

        let error = resolve_with_local_parents(root, &child_pom, &xml)
            .expect_err("a chain past the limit must be rejected");
        assert!(
            error.to_string().contains("parent chain exceeds the limit"),
            "unexpected error: {error}"
        );
    }

    /// A local parent over the project input limit is a rejected parent, not an
    /// unbounded read: resolution falls through to the repository and the walk
    /// reports nothing, so both agree.
    #[test]
    fn oversized_local_parent_is_rejected() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let root = tmp_dir.path();
        std::fs::write(
            root.join("pom.xml"),
            vec![b'x'; rv_config::MAX_PROJECT_INPUT_SIZE + 1],
        )
        .unwrap();
        let module_dir = root.join("module");
        std::fs::create_dir_all(&module_dir).unwrap();
        let pom_path = module_dir.join("pom.xml");
        let xml = child_xml("child", "parent", "../pom.xml");
        std::fs::write(&pom_path, &xml).unwrap();

        let mut resolver = ParentResolverBase::new(Some(module_dir), MockFetcher, false);
        resolver.project_root = Some(root.to_path_buf());
        let parent = Parent {
            group_id: "com.example".to_string(),
            artifact_id: "parent".to_string(),
            version: "1.0.0".to_string(),
            relative_path: Some("../pom.xml".to_string()),
        };

        assert!(resolver.load_local_parent(&parent).is_none());
        assert!(walk_parents(&pom_path, &xml, root).is_empty());
    }

    /// An oversized `.mvn/maven.config` is ignored rather than read whole.
    #[test]
    fn parse_maven_config_rejects_oversized_input() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let mvn_dir = tmp_dir.path().join(".mvn");
        std::fs::create_dir(&mvn_dir).unwrap();
        let mut content = b"-Drevision=1.0.0\n".to_vec();
        content.resize(rv_config::MAX_PROJECT_INPUT_SIZE + 1, b'\n');
        std::fs::write(mvn_dir.join("maven.config"), content).unwrap();

        assert!(parse_maven_config(tmp_dir.path()).is_empty());
    }

    /// The async reader bounds the same input as its sync sister.
    #[tokio::test]
    async fn parse_maven_config_async_rejects_oversized_input() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let mvn_dir = tmp_dir.path().join(".mvn");
        std::fs::create_dir(&mvn_dir).unwrap();
        let mut content = b"-Drevision=1.0.0\n".to_vec();
        content.resize(rv_config::MAX_PROJECT_INPUT_SIZE + 1, b'\n');
        std::fs::write(mvn_dir.join("maven.config"), content).unwrap();

        assert!(parse_maven_config_async(tmp_dir.path()).await.is_empty());
    }

    #[test]
    fn local_parent_boundary_widens_only_for_a_lone_module() {
        let root = Path::new("/workspace/module");

        assert_eq!(local_parent_boundary(root, 1), Path::new("/workspace"));
        assert_eq!(local_parent_boundary(root, 2), root);
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

    #[test]
    fn parse_maven_config_handles_standalone_d_switch() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let mvn_dir = tmp_dir.path().join(".mvn");
        std::fs::create_dir(&mvn_dir).unwrap();
        std::fs::write(
            mvn_dir.join("maven.config"),
            "-D\nrevision=4.1.0\n-D\napache.snapshots\n",
        )
        .unwrap();

        let props = parse_maven_config(tmp_dir.path());
        assert_eq!(props.get("revision").map(String::as_str), Some("4.1.0"));
        assert_eq!(
            props.get("apache.snapshots").map(String::as_str),
            Some("true")
        );
    }
}
