//! Local `<relativePath>` parents and activation-context construction.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use foldhash::{HashMap, HashSet, HashSetExt};
use rv_config::{Config, ConfigError};
use rv_lock::Platform;
use rv_maven_model::{
    ActivationContext, ImportCoord, MAX_PARENT_CHAIN_DEPTH, ModelSource, Parent, ParentLookup, Pom,
    PomError, Provenance, parent_has_expression,
};

use crate::parsed_pom_cache::ParsedPomCache;
use crate::util::{lock, pom_matches_parent};

/// The local `<relativePath>` parents one build may read: those reached
/// from the directory of the POM being built that stay inside a boundary.
/// See [`accept_local_parent`] for what a hop must pass.
#[derive(Clone, Debug, Default)]
pub(crate) struct LocalParents {
    within: Option<(PathBuf, PathBuf)>,
    /// Where the lookups' answers are kept, when they are.
    cache: Option<Arc<LocalParentCache>>,
}

/// The local parent lookups of one resolution and their answers. Every
/// module model a reactor builds reads the same parents from the working
/// tree, and each lookup canonicalizes paths and reads a file, which costs
/// most on Windows.
#[derive(Debug, Default)]
pub(crate) struct LocalParentCache {
    parsed: Arc<ParsedPomCache>,
    /// Each lookup once, also when threads ask for it at the same time, so
    /// a parent that fails warns once.
    found: Mutex<HashMap<LocalParentKey, Arc<OnceLock<Option<Pom>>>>>,
}

/// The directory a parent is looked up from, its boundary, and the parent.
type LocalParentKey = (PathBuf, PathBuf, Parent);

impl LocalParentCache {
    pub(crate) fn new(parsed: Arc<ParsedPomCache>) -> Self {
        Self {
            parsed,
            found: Mutex::default(),
        }
    }

    pub(crate) fn parsed(&self) -> &ParsedPomCache {
        &self.parsed
    }
}

impl LocalParents {
    /// No local parents, as for a POM read from a repository.
    pub(crate) fn none() -> Self {
        Self::default()
    }

    pub(crate) fn new(base_dir: PathBuf, boundary: PathBuf) -> Self {
        Self {
            within: Some((base_dir, boundary)),
            cache: None,
        }
    }

    pub(crate) fn cached_in(self, cache: Arc<LocalParentCache>) -> Self {
        Self {
            cache: Some(cache),
            ..self
        }
    }

    pub(crate) fn load(&self, parent: &Parent) -> Option<Pom> {
        let (base_dir, boundary) = self.within.as_ref()?;
        let Some(cache) = self.cache.as_deref() else {
            return accept_local_parent(base_dir, boundary, parent, None).map(|hop| hop.pom);
        };
        let key = (base_dir.clone(), boundary.clone(), parent.clone());
        let found = Arc::clone(lock(&cache.found).entry(key).or_default());
        found
            .get_or_init(|| {
                accept_local_parent(base_dir, boundary, parent, Some(&cache.parsed))
                    .map(|hop| hop.pom)
            })
            .clone()
    }
}

/// Reactor discovery reads accepted local parents only. Its POMs are the
/// user's, so their repositories are marked as declared by the user.
impl ModelSource for LocalParents {
    type Error = PomError;

    async fn parent(
        &self,
        parent: &mut Parent,
        _lookup: ParentLookup,
    ) -> Result<Option<Pom>, PomError> {
        if let Some(mut pom) = self.load(parent) {
            pom.mark_root_repositories();
            return Ok(Some(pom));
        }
        if !parent_has_expression(parent) {
            // A version that a repository lookup would reject fails here too.
            crate::resolver::parent_coord(parent)?;
        }
        Ok(None)
    }

    async fn import(&self, _bom: ImportCoord<'_>) -> Result<Option<Pom>, PomError> {
        Ok(None)
    }
}

/// Validate the parsed POM matches `parent` and resolve any nested
/// `<parent>/<relativePath>` to absolute so the walk continues correctly.
fn read_and_validate_pom(
    path: &Path,
    contents: &[u8],
    parent: &Parent,
    suppress_logs: bool,
    parsed: Option<&ParsedPomCache>,
) -> Option<Pom> {
    let pom = match parsed {
        Some(parsed) => parsed.parse(&rv_maven_types::BlobId::from_bytes(contents), contents),
        None => rv_maven_model::decode_pom(contents).and_then(|xml| Pom::parse(&xml).map(Arc::new)),
    };
    let mut pom = match pom {
        Ok(pom) => Arc::unwrap_or_clone(pom),
        Err(e) => {
            if !suppress_logs {
                tracing::warn!(
                    sec_code = "POM_PROBLEM",
                    path = %path.display(),
                    error = %e,
                    "cannot parse the local parent POM; looking it up in the repositories"
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

    anchor_parent_path(&mut pom, path);
    Some(pom)
}

/// Make `pom`'s `<relativePath>` absolute, against `path`, where `pom` was
/// read from, so its parent is looked up from there whoever reads it.
pub(crate) fn anchor_parent_path(pom: &mut Pom, path: &Path) {
    if let Some(parent_ref) = &mut pom.parent {
        let relative = relative_path_text(parent_ref);
        if !relative.is_empty()
            && let Some(parent_dir) = path.parent()
        {
            let mut resolved = rv_fs::join_pom_entry(parent_dir, relative);
            // The absolute path loses the entry's own spelling, which Windows
            // trims differently once `pom.xml` follows it, so pick the file
            // while the entry is still known.
            if cfg!(windows) && resolved.is_dir() {
                resolved = rv_fs::join_pom_entry_pom_xml(parent_dir, relative);
            }
            parent_ref.relative_path = Some(resolved.to_string_lossy().to_string());
        }
    }
}

/// The `<relativePath>` as Maven reads it: trimmed like all element text
/// (Java's `String.trim()`), and `../pom.xml` when absent.
fn relative_path_text(parent: &Parent) -> &str {
    parent
        .relative_path
        .as_deref()
        .map_or("../pom.xml", |path| path.trim_matches(|c| c <= ' '))
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
    boundary: &Path,
    parent: &Parent,
    parsed: Option<&ParsedPomCache>,
) -> Option<LocalParentHop> {
    let relative = relative_path_text(parent);
    if relative.is_empty() {
        return None;
    }
    let mut path = rv_fs::join_pom_entry(base_dir, relative);

    // Reject `<relativePath>` values that escape the project tree (e.g.
    // `<relativePath>../../../../etc/passwd</relativePath>`); fall through
    // to remote resolution.
    if !path_within_root(&path, boundary) {
        tracing::debug!(
            relative_path = %rv_maven_types::bounded(relative),
            "relativePath escapes project root; falling back to remote resolution"
        );
        return None;
    }

    if let Ok(metadata) = std::fs::metadata(&path)
        && metadata.is_dir()
    {
        path = directory_pom(base_dir, boundary, relative)?;
    }

    let mut pom = match rv_config::read_project_input(&path) {
        Ok(contents) => read_and_validate_pom(&path, &contents, parent, false, parsed)?,
        Err(e) if io_error_kind(&e) == Some(std::io::ErrorKind::IsADirectory) => {
            // Pre-check missed a directory (TOCTOU); retry with pom.xml appended.
            path = directory_pom(base_dir, boundary, relative)?;
            let contents = rv_config::read_project_input(&path).ok()?;
            read_and_validate_pom(&path, &contents, parent, true, parsed)?
        }
        Err(e) => {
            if io_error_kind(&e) != Some(std::io::ErrorKind::NotFound) {
                tracing::warn!(
                    sec_code = "POM_PROBLEM",
                    path = %rv_maven_types::bounded(&path.display().to_string()),
                    error = %rv_maven_types::bounded(&e.to_string()),
                    "cannot read the local parent POM; looking it up in the repositories"
                );
            }
            return None;
        }
    };
    pom.set_provenance(Provenance::LocalParent { path: path.clone() });
    Some(LocalParentHop { path, pom })
}

/// The `pom.xml` read when `relative` names a directory. It can be a symlink
/// out of the directory that passed the containment check, and on Windows it
/// can sit in a sibling of it (`parent..` is checked as `parent`, its POM is
/// `parent..\pom.xml`), so it is checked itself.
fn directory_pom(base_dir: &Path, boundary: &Path, relative: &str) -> Option<PathBuf> {
    let pom = rv_fs::join_pom_entry_pom_xml(base_dir, relative);
    path_within_root(&pom, boundary).then_some(pom)
}

fn io_error_kind(error: &ConfigError) -> Option<std::io::ErrorKind> {
    match error {
        ConfigError::ProjectInputIo { source, .. } => Some(source.kind()),
        _ => None,
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
/// Reactor discovery, `raeva sync`'s model hashing, and resolution all derive
/// their boundary here, so all three accept exactly the same set of local
/// parents.
pub(crate) fn local_parent_boundary(root: &Path, module_count: usize) -> PathBuf {
    if module_count == 1 {
        root.parent().unwrap_or(root).to_path_buf()
    } else {
        root.to_path_buf()
    }
}

/// Walk the chain of local parent POMs reachable from `pom_path` (parsed as
/// `pom`) via `<parent><relativePath>`, in child-to-ancestor order.
///
/// This is the one accepted-local-parent traversal: a hop is yielded only when
/// resolution itself would load that file as the parent, i.e. it stays inside
/// `boundary` after symlink-aware canonicalization, exists, is within the
/// project input size limit, parses, and declares the coordinates the child
/// wrote in its `<parent>`, compared as written the way Maven compares them.
/// The walk stops at the first hop that fails any of those, and at a cycle.
///
/// Depth is bounded by [`MAX_PARENT_CHAIN_DEPTH`], the same limit inheritance
/// resolution applies: a chain within the limit is reported in full, and a
/// chain that needs one more hop is rejected by inheritance itself, so no
/// resolution result can depend on a parent this walk did not report.
///
/// Callers derive `boundary` from [`local_parent_boundary`].
pub(crate) fn accepted_local_parents(
    pom_path: &Path,
    pom: &Pom,
    boundary: &Path,
    parsed: Option<&ParsedPomCache>,
) -> Vec<PathBuf> {
    let mut chain = Vec::new();
    let mut pom = std::borrow::Cow::Borrowed(pom);
    let mut seen: HashSet<PathBuf> = HashSet::new();
    seen.insert(canonical_or_owned(pom_path));
    let mut base_dir = pom_path.parent().unwrap_or(Path::new(".")).to_path_buf();

    for _ in 0..MAX_PARENT_CHAIN_DEPTH {
        let Some(parent) = pom.parent.as_ref() else {
            break;
        };
        let Some(hop) = accept_local_parent(&base_dir, boundary, parent, parsed) else {
            break;
        };
        if !seen.insert(canonical_or_owned(&hop.path)) {
            break;
        }
        base_dir = hop.path.parent().unwrap_or(Path::new(".")).to_path_buf();
        chain.push(hop.path);
        pom = std::borrow::Cow::Owned(hop.pom);
    }

    chain
}

fn canonical_or_owned(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// True when `candidate` resolves inside `root`. Canonicalizes the deepest
/// existing prefix so symlink targets are honored; fails closed (returns
/// false) when canonicalization fails.
fn path_within_root(candidate: &Path, root: &Path) -> bool {
    let Ok(root_canonical) = rv_fs::canonicalize_existing_prefix(root) else {
        return false;
    };
    let Ok(candidate_canonical) = rv_fs::canonicalize_existing_prefix(candidate) else {
        return false;
    };
    candidate_canonical.starts_with(&root_canonical)
}

/// Async mirror of [`rv_config::read_project_input`]: the same
/// [`rv_config::MAX_PROJECT_INPUT_SIZE`] bound, applied without blocking the
/// executor, so an oversize project input cannot drive an unbounded allocation
/// on an async path.
pub(crate) async fn read_project_input_async(path: &Path) -> Result<Vec<u8>, ConfigError> {
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
    Ok(bytes)
}

/// The activation context of a reactor discovery or model resolution for
/// `target_platform`, the host when `None`. Discovery overlays the reactor
/// root's `.mvn/maven.config` on it.
pub(crate) fn build_activation_context(
    base_dir: Option<PathBuf>,
    config: &Config,
    target_platform: Option<&Platform>,
) -> ActivationContext {
    // Maven activates `<os>` profiles against the build target, so a
    // `--platforms macos-aarch64` pass on Linux activates the macOS ones.
    let environment = match target_platform {
        Some(target) => config.model_environment(target.os(), target.arch(), target.jdk()),
        None => config.host().host_environment(),
    };
    let settings_properties = config.settings_profile_properties_for(&environment);
    let mut ctx = ActivationContext::new(environment);
    ctx.base_dir = base_dir;
    ctx.active_profiles = config.active_profiles().to_vec();
    ctx.inactive_profiles = config.inactive_profiles.clone();
    ctx.settings_properties = settings_properties;
    ctx.settings_property_names = config.defined_settings_properties();
    ctx
}

#[cfg(test)]
mod tests {
    use super::*;
    use rv_config::ResolvedPaths;
    use rv_maven_model::EffectiveDescriptor;

    fn pom(
        artifact_id: &str,
        version: &str,
        properties: &str,
        parent: Option<(&str, &str, &str)>,
    ) -> String {
        let parent = parent.map_or_else(String::new, |(artifact_id, version, relative_path)| {
            format!(
                "<parent><groupId>com.example</groupId><artifactId>{artifact_id}</artifactId>\
                 <version>{version}</version><relativePath>{relative_path}</relativePath></parent>"
            )
        });
        format!(
            "<project><modelVersion>4.0.0</modelVersion>{properties}{parent}\
             <groupId>com.example</groupId><artifactId>{artifact_id}</artifactId>\
             <version>{version}</version><packaging>pom</packaging></project>"
        )
    }

    fn pom_xml(artifact_id: &str) -> String {
        pom(artifact_id, "1.0.0", "", None)
    }

    fn child_xml(artifact_id: &str, parent_artifact_id: &str, relative_path: &str) -> String {
        pom(
            artifact_id,
            "1.0.0",
            "",
            Some((parent_artifact_id, "1.0.0", relative_path)),
        )
    }

    fn write(root: &Path, files: &[(&str, String)]) {
        for (path, contents) in files {
            let path = root.join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, contents).unwrap();
        }
    }

    fn parent(artifact_id: &str, version: &str, relative_path: Option<&str>) -> Parent {
        Parent {
            group_id: "com.example".to_string(),
            artifact_id: artifact_id.to_string(),
            version: version.to_string(),
            relative_path: relative_path.map(str::to_string),
        }
    }

    fn walk_parents(pom_path: &Path, pom_xml: &str, boundary: &Path) -> Vec<PathBuf> {
        accepted_local_parents(pom_path, &Pom::parse(pom_xml).unwrap(), boundary, None)
    }

    fn walked(pom_path: &Path, pom_xml: &str, boundary: &Path) -> Vec<PathBuf> {
        walk_parents(pom_path, pom_xml, boundary)
            .iter()
            .map(|path| canonical_or_owned(path))
            .collect()
    }

    fn canonical(paths: &[PathBuf]) -> Vec<PathBuf> {
        paths.iter().map(|path| canonical_or_owned(path)).collect()
    }

    /// Builds with local parents only and goes on without any other
    /// parent, as reactor discovery does. `user_properties` from
    /// `.mvn/maven.config` are overlaid on the starting POM before
    /// inheritance, as the resolver does with the reactor root's config.
    fn resolve_with_local_parents(
        root: &Path,
        child_pom: &Path,
        xml: &str,
        user_properties: &[(&str, &str)],
    ) -> Result<EffectiveDescriptor, PomError> {
        const DISCOVERY: rv_maven_model::ModelPolicy = rv_maven_model::ModelPolicy {
            root: true,
            missing_parent: rv_maven_model::MissingParent::InheritDeclaredCoordinates,
        };
        let local = LocalParents::new(
            child_pom.parent().unwrap().to_path_buf(),
            root.to_path_buf(),
        );
        let mut pom = Pom::parse(xml)?;
        for (key, value) in user_properties {
            pom.properties.insert(*key, *value);
        }
        rv_maven_model::ready(EffectiveDescriptor::build(
            pom,
            &local,
            DISCOVERY,
            &ActivationContext::default(),
        ))
    }

    /// The OS properties come from the TARGET platform, so `--platforms
    /// macos-aarch64` activates macOS profiles on a Linux CI, and from the
    /// host when there is none.
    #[test]
    fn activation_context_follows_the_target_platform() {
        let paths = ResolvedPaths::for_testing().expect("paths");
        let config = Config::for_testing_with_repos(PathBuf::from("."), paths, Vec::new());
        for (os, arch, name, jvm_arch, separator) in [
            ("macos", "aarch64", "Mac OS X", "aarch64", ':'),
            ("darwin", "arm64", "Mac OS X", "aarch64", ':'),
            ("windows", "x86_64", "Windows 11", "amd64", ';'),
            ("linux", "x86_64", "Linux", "amd64", ':'),
            ("CustomOS", "x86_64", "CustomOS", "amd64", ':'),
        ] {
            let target = Platform::new(os, arch).unwrap();
            let ctx = build_activation_context(None, &config, Some(&target));
            assert_eq!(ctx.property("os.name"), Some(name), "{target}");
            assert_eq!(ctx.property("os.arch"), Some(jvm_arch), "{target}");
            assert_eq!(ctx.property("os.family"), None, "{target}");
            assert_eq!(ctx.path_separator(), Some(separator), "{target}");
        }
        if let Ok(host) = Platform::current() {
            let ctx = build_activation_context(None, &config, None);
            let target = build_activation_context(None, &config, Some(&host));
            for name in ["os.name", "os.arch"] {
                assert!(ctx.property(name).is_some(), "{name}");
                assert_eq!(ctx.property(name), target.property(name), "{name}");
            }
        }

        let windows = Platform::new("windows", "x86_64").unwrap();
        let ctx = build_activation_context(Some(PathBuf::from("base")), &config, Some(&windows));
        assert_eq!(ctx.base_dir.as_deref(), Some(Path::new("base")));
        assert_eq!(ctx.property("os.name"), Some("Windows 11"));
    }

    /// Security: a local parent is read from a `<relativePath>` file or
    /// directory inside the boundary and nowhere else. A path escaping the
    /// boundary, a POM with other coordinates, one over the input limit and
    /// an empty `<relativePath/>` all fall through to the repository.
    #[test]
    fn local_parents_load_only_a_contained_matching_parent() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("project");
        let module = root.join("module");
        write(
            tmp.path(),
            &[
                ("outside/pom.xml", pom_xml("evil")),
                ("project/pom.xml", pom_xml("root")),
                ("project/sub/pom.xml", pom_xml("parent")),
                (
                    "project/big/pom.xml",
                    "x".repeat(rv_config::MAX_PROJECT_INPUT_SIZE + 1),
                ),
                ("project/module/pom.xml", String::new()),
            ],
        );
        for (boundary, artifact_id, version, relative_path, found) in [
            (&root, "parent", "1.0.0", Some("../sub"), true),
            (&root, "root", "1.0.0", Some("../"), true),
            (&root, "root", "1.0.0", None, true),
            (&root, "root", "1.0.0", Some(""), false),
            (&root, "root", "9.9.9", Some("../pom.xml"), false),
            (&module, "root", "1.0.0", Some("../"), false),
            (&root, "evil", "1.0.0", Some("../../outside"), false),
            (&root, "parent", "1.0.0", Some("../big/pom.xml"), false),
        ] {
            let local = LocalParents::new(module.clone(), boundary.clone());
            let loaded = local.load(&parent(artifact_id, version, relative_path));
            assert_eq!(
                loaded.as_ref().and_then(|pom| pom.artifact_id.as_deref()),
                found.then_some(artifact_id),
                "{artifact_id}:{version} at {relative_path:?}"
            );
        }

        let loaded = LocalParents::new(root.clone(), root.clone())
            .load(&parent("parent", "1.0.0", Some("sub")))
            .expect("a directory relativePath names its pom.xml");
        assert_eq!(
            loaded.provenance(),
            Some(&Provenance::LocalParent {
                path: root.join("sub").join("pom.xml")
            })
        );
    }

    /// The walk reports every local parent resolution reads, with
    /// `<relativePath>` trimmed as Maven trims element text, up to the shared
    /// depth limit. Past it resolution rejects the chain, so no parent takes
    /// part in a resolution while sitting outside the model hash.
    #[test]
    fn accepted_local_parents_walks_the_chain_resolution_reads() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let xml = child_xml("child", "parent", "\n    ../pom.xml\n  ");
        write(
            root,
            &[
                ("pom.xml", pom_xml("grandparent")),
                (
                    "a/pom.xml",
                    child_xml("parent", "grandparent", " ../pom.xml "),
                ),
                ("a/b/pom.xml", xml.clone()),
            ],
        );
        let child = root.join("a/b/pom.xml");
        assert_eq!(
            walked(&child, &xml, root),
            canonical(&[root.join("a/pom.xml"), root.join("pom.xml")])
        );
        assert!(walk_parents(&child, &child_xml("child", "parent", " "), root).is_empty());

        for length in [MAX_PARENT_CHAIN_DEPTH, MAX_PARENT_CHAIN_DEPTH + 1] {
            let tmp = tempfile::tempdir().unwrap();
            let root = tmp.path();
            let mut files: Vec<(String, String)> = (1..=length)
                .map(|index| {
                    let name = format!("p{index}");
                    let xml = if index < length {
                        let next = format!("p{}", index + 1);
                        child_xml(&name, &next, &format!("../{next}/pom.xml"))
                    } else {
                        pom_xml(&name)
                    };
                    (format!("{name}/pom.xml"), xml)
                })
                .collect();
            let xml = child_xml("child", "p1", "../p1/pom.xml");
            files.push(("child/pom.xml".to_string(), xml.clone()));
            let files: Vec<(&str, String)> = files
                .iter()
                .map(|(path, xml)| (path.as_str(), xml.clone()))
                .collect();
            write(root, &files);
            let child = root.join("child/pom.xml");

            let chain = walked(&child, &xml, root);
            assert_eq!(chain.len(), MAX_PARENT_CHAIN_DEPTH);
            let deepest = root.join(format!("p{MAX_PARENT_CHAIN_DEPTH}/pom.xml"));
            assert_eq!(chain.last(), canonical(&[deepest]).first());
            let resolved = resolve_with_local_parents(root, &child, &xml, &[]);
            if length > MAX_PARENT_CHAIN_DEPTH {
                let error = resolved.expect_err("a chain past the limit must be rejected");
                assert!(
                    error.to_string().contains("parent chain exceeds the limit"),
                    "{error}"
                );
            } else {
                resolved.expect("a chain at the limit resolves");
            }
        }
    }

    /// Security: the walk must not read or report a file resolution would not
    /// read as the parent, which would put an arbitrary local path and digest
    /// into the commit-bound lockfile's model hash: one outside the boundary,
    /// also through a symlink, one with other coordinates, or one over the
    /// input limit.
    #[test]
    fn accepted_local_parents_rejects_what_resolution_would_not_read() {
        let tmp = tempfile::tempdir().unwrap();
        let boundary = tmp.path().join("project");
        write(
            tmp.path(),
            &[
                ("outside/pom.xml", pom_xml("evil")),
                ("project/pom.xml", pom_xml("actual-parent")),
                (
                    "project/big/pom.xml",
                    "x".repeat(rv_config::MAX_PROJECT_INPUT_SIZE + 1),
                ),
            ],
        );
        let module_pom = boundary.join("module/pom.xml");
        for (artifact_id, relative_path) in [
            ("evil", "../../outside/pom.xml"),
            ("declared-parent", "../pom.xml"),
            ("parent", "../big/pom.xml"),
        ] {
            let xml = child_xml("child", artifact_id, relative_path);
            write(&boundary, &[("module/pom.xml", xml.clone())]);
            assert!(
                walk_parents(&module_pom, &xml, &boundary).is_empty(),
                "{relative_path}"
            );
        }

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(tmp.path().join("outside"), boundary.join("escape"))
                .unwrap();
            let xml = child_xml("child", "evil", "escape/pom.xml");
            assert!(walk_parents(&boundary.join("pom.xml"), &xml, &boundary).is_empty());

            std::fs::create_dir(boundary.join("linked")).unwrap();
            std::os::unix::fs::symlink(
                tmp.path().join("outside/pom.xml"),
                boundary.join("linked/pom.xml"),
            )
            .unwrap();
            let xml = child_xml("child", "evil", "linked");
            assert!(walk_parents(&boundary.join("pom.xml"), &xml, &boundary).is_empty());
        }
    }

    /// Maven does not expand `<parent>` before looking it up. The CI-friendly
    /// `${revision}` pattern works because parent and child both write it,
    /// so the coordinates match as written and the property only expands in
    /// the effective model. A child property, a `.mvn/maven.config` user
    /// property or a version the parent never had names no local parent, and
    /// Maven fails with "Non-resolvable parent POM".
    #[test]
    fn a_parent_version_is_matched_as_written() {
        let revision =
            |version: &str| format!("<properties><revision>{version}</revision></properties>");
        for (parent_version, parent_properties, child_properties, declared, user, effective) in [
            (
                "${revision}",
                revision("7.7.7"),
                String::new(),
                "${revision}",
                None,
                Some("7.7.7"),
            ),
            (
                "2.0.0",
                String::new(),
                revision("2.0.0"),
                "${revision}",
                None,
                None,
            ),
            (
                "1.2.3",
                String::new(),
                String::new(),
                "${parentVersion}",
                Some(("parentVersion", "1.2.3")),
                None,
            ),
            (
                "1.0.0",
                String::new(),
                revision("9.9.9"),
                "${revision}",
                None,
                None,
            ),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let root = tmp.path();
            let xml = pom(
                "child",
                declared,
                &child_properties,
                Some(("parent", declared, "../pom.xml")),
            );
            write(
                root,
                &[
                    (
                        "pom.xml",
                        pom("parent", parent_version, &parent_properties, None),
                    ),
                    ("module/pom.xml", xml.clone()),
                ],
            );
            let child = root.join("module/pom.xml");
            let resolved = resolve_with_local_parents(root, &child, &xml, user.as_slice());
            match effective {
                Some(version) => {
                    assert_eq!(
                        walked(&child, &xml, root),
                        canonical(&[root.join("pom.xml")])
                    );
                    assert_eq!(resolved.expect("resolves").gav.version, version);
                }
                None => {
                    assert!(walk_parents(&child, &xml, root).is_empty(), "{declared}");
                    assert!(
                        matches!(resolved, Err(PomError::ParentExpression(_))),
                        "{declared}: {resolved:?}"
                    );
                }
            }
        }

        // A property a parent declares cannot name that parent's own parent,
        // so the walk stops at the hop inheritance cannot resolve.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let xml = pom(
            "child",
            "1.0.0",
            "",
            Some(("mid", "2.0.0", "../mid/pom.xml")),
        );
        write(
            root,
            &[
                (
                    "top/pom.xml",
                    pom(
                        "top",
                        "3.0.0",
                        "<properties><toprev>3.0.0</toprev></properties>",
                        None,
                    ),
                ),
                (
                    "mid/pom.xml",
                    pom(
                        "mid",
                        "2.0.0",
                        "",
                        Some(("top", "${toprev}", "../top/pom.xml")),
                    ),
                ),
                ("child/pom.xml", xml.clone()),
            ],
        );
        assert_eq!(
            walked(&root.join("child/pom.xml"), &xml, root),
            canonical(&[root.join("mid/pom.xml")])
        );
    }

    /// Outside Windows a trailing dot is part of the name, as it is for Maven.
    #[cfg(not(windows))]
    #[test]
    fn accepted_local_parents_keeps_a_trailing_dot_outside_windows() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write(
            root,
            &[
                ("parent/pom.xml", pom_xml("parent")),
                ("child/pom.xml", String::new()),
            ],
        );
        let child = root.join("child/pom.xml");
        let xml = child_xml("child", "parent", "../parent.");
        assert!(walk_parents(&child, &xml, root).is_empty());

        write(root, &[("parent./pom.xml", pom_xml("parent"))]);
        assert_eq!(
            walked(&child, &xml, root),
            canonical(&[root.join("parent./pom.xml")])
        );
    }

    /// Maven opens a `<relativePath>` as a plain Windows path, which loses a
    /// trailing dot or space where Win32 normalization trims one. Discovery
    /// starts from a `\\?\` root, where nothing is trimmed unless raeva does it.
    #[cfg(windows)]
    #[test]
    fn accepted_local_parents_trims_a_relative_path_as_windows_does() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp_dir.path()).unwrap();
        let child_dir = root.join("child");
        std::fs::create_dir_all(&child_dir).unwrap();
        std::fs::create_dir_all(root.join("parent")).unwrap();
        std::fs::create_dir_all(root.join("grand")).unwrap();
        std::fs::write(root.join("grand").join("pom.xml"), pom_xml("grandparent")).unwrap();
        std::fs::write(
            root.join("parent").join("pom.xml"),
            child_xml("parent", "grandparent", "../grand. "),
        )
        .unwrap();
        let child_pom = child_dir.join("pom.xml");
        let expected = [
            std::fs::canonicalize(root.join("parent").join("pom.xml")).unwrap(),
            std::fs::canonicalize(root.join("grand").join("pom.xml")).unwrap(),
        ];

        for relative in [
            "../parent./pom.xml",
            "../parent.",
            "../parent. ",
            "..\\parent.\\",
        ] {
            let xml = child_xml("child", "parent", relative);
            let chain: Vec<PathBuf> = walk_parents(&child_pom, &xml, &root)
                .iter()
                .map(|path| canonical_or_owned(path))
                .collect();
            assert_eq!(chain, expected, "{relative:?}");
        }
        // Win32 keeps these spellings in front of `\pom.xml`, so Maven finds
        // no local parent either.
        for relative in [
            "../parent. /pom.xml",
            "../parent../pom.xml",
            "../parent..",
            "../parent .",
            "../parent. .",
        ] {
            let xml = child_xml("child", "parent", relative);
            assert!(
                walk_parents(&child_pom, &xml, &root).is_empty(),
                "{relative:?}"
            );
        }
    }

    /// `../parent..` passes the containment check as `parent`, but Maven reads
    /// its POM from `parent..`, here a junction out of the boundary.
    #[cfg(windows)]
    #[test]
    fn accepted_local_parents_checks_the_directory_a_windows_pom_is_read_from() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(tmp_dir.path()).unwrap();
        let boundary = base.join("project");
        let module_dir = boundary.join("module");
        std::fs::create_dir_all(&module_dir).unwrap();
        std::fs::create_dir_all(boundary.join("parent")).unwrap();
        let outside = base.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("pom.xml"), pom_xml("evil")).unwrap();
        rv_test_support::create_junction(&boundary.join("parent.."), &outside).unwrap();

        let pom_path = module_dir.join("pom.xml");
        let xml = child_xml("child", "evil", "../parent..");
        std::fs::write(&pom_path, &xml).unwrap();
        assert!(walk_parents(&pom_path, &xml, &boundary).is_empty());

        let resolver = LocalParents::new(module_dir, boundary.clone());
        let parent = Parent {
            group_id: "com.example".to_string(),
            artifact_id: "evil".to_string(),
            version: "1.0.0".to_string(),
            relative_path: Some("../parent..".to_string()),
        };
        assert!(resolver.load(&parent).is_none());

        // The same POM inside the boundary is read, so the rejection above
        // comes from the junction.
        std::fs::remove_dir(boundary.join("parent..")).unwrap();
        std::fs::create_dir_all(boundary.join("parent..")).unwrap();
        std::fs::write(boundary.join("parent..").join("pom.xml"), pom_xml("evil")).unwrap();
        assert_eq!(walk_parents(&pom_path, &xml, &boundary).len(), 1);
    }

    #[test]
    fn local_parent_boundary_widens_only_for_a_lone_module() {
        let root = Path::new("/workspace/module");

        assert_eq!(local_parent_boundary(root, 1), Path::new("/workspace"));
        assert_eq!(local_parent_boundary(root, 2), root);
    }
}
