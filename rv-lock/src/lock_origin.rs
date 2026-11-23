//! How raeva.lock spells a repository origin.
//!
//! A `file:` repository inside the directory that holds raeva.lock is recorded
//! as a project-relative token, `./<segment>/.../`, so a checkout at another
//! path records the same origin. One outside it that shares a named directory
//! with it is recorded from there, `../<segment>/.../`, with a `../` for each
//! level up, so the tree holding both can move. Every other origin is
//! recorded as the URL it was declared with.
//!
//! A token is only ever a lookup key: [`LockOrigins::declared`] maps a
//! repository that current configuration or the current POMs declare to the
//! key the lock would record for it, and a lock origin grants access only by
//! equalling the key of such a declaration. Nothing here joins a token to the
//! project root to produce a location to read from.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use url::Url;

use rv_config::redact_url;
use rv_maven_types::is_terminal_safe;

use crate::error::LockError;
use crate::lock::RepoIds;
use rv_fs::plain_path;

pub(crate) const PROJECT_RELATIVE_ORIGIN_PREFIX: &str = "./";
pub(crate) const PARENT_ORIGIN_PREFIX: &str = "../";

/// Lockfile `[metadata]` key under which `raeva sync` records `origin\tid` lines
/// for the id'd repositories that backed resolution, so `raeva export-m2` can
/// label `_remote.repositories` markers for repositories only a POM declares.
const LOCK_REPO_IDS_KEY: &str = "repo_ids";

/// Normalizes a repository URL to a trailing-slash form.
///
/// Trims whitespace and appends a trailing slash if one is not already
/// present, so URL comparison and path joining stay consistent. A `file:`
/// URL is spelled as a fetch parses it, so that `${project.basedir}`'s
/// native separators on Windows and a configured URL for the same directory
/// compare equal. That reads only the text, never the filesystem.
pub fn normalize_repo_url(url: &str) -> String {
    let trimmed = url.trim();
    if let Ok(mut file) = Url::parse(trimmed)
        && file.scheme() == "file"
    {
        if !file.path().ends_with('/') {
            let path = format!("{}/", file.path());
            file.set_path(&path);
        }
        return file.into();
    }
    if trimmed.ends_with('/') {
        trimmed.to_string()
    } else {
        format!("{trimmed}/")
    }
}

/// [`Url::to_file_path`], or `None` where it would give no absolute path:
/// on Windows a host without a share or a drive without a path, which `url`
/// asserts against in debug builds. A POM can declare either.
pub fn file_url_path(url: &Url) -> Option<PathBuf> {
    if cfg!(windows) {
        let mut segments = url.path_segments()?;
        let first = segments.next().unwrap_or_default();
        let usable = match url.host() {
            None | Some(url::Host::Domain("localhost")) => segments.next().is_some(),
            // The share is the decoded first segment up to a separator, so
            // one that starts with an encoded separator leaves `\\host\`
            // without a share.
            Some(_) => {
                let separator =
                    |at: &str| ["%2f", "%5c"].iter().any(|s| at.eq_ignore_ascii_case(s));
                !first.is_empty() && !first.get(..3).is_some_and(separator)
            }
        };
        if !usable {
            return None;
        }
    }
    url.to_file_path().ok()
}

/// True when `url` parses as HTTP or HTTPS, using the fetch layer's parser.
/// Such origins match only HTTP(S) declarations, which compare as text.
pub fn is_http_origin(url: &str) -> bool {
    Url::parse(url.trim()).is_ok_and(|url| matches!(url.scheme(), "http" | "https"))
}

/// True when `value` is spelled as a project-relative origin. Whether it is a
/// valid one is `validate_project_relative_origin`'s question.
pub fn is_project_relative_origin(value: &str) -> bool {
    value.trim_start().starts_with('.')
}

/// Check a project-relative origin exactly as written: `./` or one or more
/// `../`, then zero or more `segment/`. The text is split on `/` rather than
/// parsed as a path, because path parsing drops repeated separators and `.`
/// components that would then name a different directory than the text
/// does.
pub(crate) fn validate_project_relative_origin(value: &str) -> Result<(), LockError> {
    // The value is not shown: text that fails this check may be a URL with
    // credentials behind a stray '.'.
    let invalid = || {
        LockError::Invalid(
            "a repository origin starting with '.' is not a valid project-relative origin; \
             expected './' or one or more '../' followed by '/'-terminated directory names"
                .to_string(),
        )
    };
    let (_, rest) = split_relative_origin(value).ok_or_else(invalid)?;
    if rest.is_empty() {
        return Ok(());
    }
    let inner = rest.strip_suffix('/').ok_or_else(invalid)?;
    if inner
        .split('/')
        .all(|segment| decode_segment(segment).is_some())
    {
        Ok(())
    } else {
        Err(invalid())
    }
}

/// The levels a project-relative origin goes up, and the segments after
/// them; `None` for text that starts with neither `./` nor `../`.
fn split_relative_origin(value: &str) -> Option<(usize, &str)> {
    if let Some(rest) = value.strip_prefix(PROJECT_RELATIVE_ORIGIN_PREFIX) {
        return Some((0, rest));
    }
    let mut rest = value.strip_prefix(PARENT_ORIGIN_PREFIX)?;
    let mut levels = 1;
    while let Some(next) = rest.strip_prefix(PARENT_ORIGIN_PREFIX) {
        rest = next;
        levels += 1;
    }
    Some((levels, rest))
}

/// Whether a token segment spells `c` as `%` and the uppercase hex of its
/// UTF-8 bytes, as a URL does: `%` and `\\`, the URL delimiters `#` and `?`,
/// whitespace, and the control and invisible characters raeva.lock refuses
/// in an origin.
fn is_escaped(c: char) -> bool {
    matches!(c, '%' | '\\' | '#' | '?')
        || c.is_whitespace()
        || !is_terminal_safe(c.encode_utf8(&mut [0; 4]))
}

/// The token segment for the directory `name`, if it has one: `name` with
/// each character [`is_escaped`] reads percent-encoded. A `/` or `:` has no
/// spelling, as either reads as a separator, a drive or a stream on Windows.
fn encode_segment(name: &str) -> Option<String> {
    if matches!(name, "" | "." | "..") || name.contains(['/', ':']) {
        return None;
    }
    let mut segment = String::with_capacity(name.len());
    for c in name.chars() {
        if is_escaped(c) {
            for byte in c.encode_utf8(&mut [0; 4]).bytes() {
                segment.push_str(&format!("%{byte:02X}"));
            }
        } else {
            segment.push(c);
        }
    }
    Some(segment)
}

/// The directory name a token segment spells. The segment must be exactly
/// [`encode_segment`]'s spelling of that name, so each name has one.
fn decode_segment(segment: &str) -> Option<String> {
    let mut bytes = Vec::with_capacity(segment.len());
    let mut rest = segment.as_bytes();
    while let Some((&byte, tail)) = rest.split_first() {
        rest = tail;
        if byte == b'%' {
            let hex = std::str::from_utf8(rest.get(..2)?).ok()?;
            bytes.push(u8::from_str_radix(hex, 16).ok()?);
            rest = &rest[2..];
        } else {
            bytes.push(byte);
        }
    }
    let name = String::from_utf8(bytes).ok()?;
    (encode_segment(&name)? == segment).then_some(name)
}

/// The project-relative origin of `path` from `root`: `./` and the names
/// below `root`, or, when `climb` allows it, a `../` for each directory of
/// `root` below the deepest one both share. Paths that share no named
/// directory, only a filesystem root, a drive or a share, have none: no move
/// of one tree carries both, so their absolute URL is the portable spelling.
fn relative_origin(root: &Path, path: &Path, climb: bool) -> Option<String> {
    let root: Vec<Component<'_>> = root.components().collect();
    let path: Vec<Component<'_>> = path.components().collect();
    let shared = root.iter().zip(&path).take_while(|(a, b)| a == b).count();
    let levels = root.len() - shared;
    if levels > 0 && !(climb && is_named(&root[..shared])) {
        return None;
    }
    let mut token = match levels {
        0 => PROJECT_RELATIVE_ORIGIN_PREFIX.to_string(),
        _ => PARENT_ORIGIN_PREFIX.repeat(levels),
    };
    for component in &path[shared..] {
        let Component::Normal(name) = component else {
            return None;
        };
        token.push_str(&encode_segment(name.to_str()?)?);
        token.push('/');
    }
    validate_project_relative_origin(&token).ok()?;
    Some(token)
}

/// Whether `components` name a directory below a filesystem root, drive or
/// share.
fn is_named(components: &[Component<'_>]) -> bool {
    (components.iter()).any(|component| matches!(component, Component::Normal(_)))
}

/// A repository origin as recorded in raeva.lock, for messages and logs: a
/// valid project-relative origin such as `./repo/` as written, anything else
/// through [`redact_url`].
pub fn redact_origin(value: &str) -> String {
    if validate_project_relative_origin(value).is_ok() {
        value.to_string()
    } else {
        redact_url(value)
    }
}

/// The key a recorded origin is looked up under among
/// [`LockOrigins::declared`] keys: a project-relative origin as written, any
/// other origin normalized.
pub fn recorded_key(recorded: &str) -> String {
    if recorded.is_empty() || is_project_relative_origin(recorded) {
        recorded.to_string()
    } else {
        normalize_repo_url(recorded)
    }
}

/// The directory a lockfile's project-relative origins are relative to, in
/// every spelling a declared `file:` URL may use for it.
#[derive(Debug, Clone)]
pub struct LockOrigins {
    roots: Vec<PathBuf>,
    /// The plain form of the canonical root, which `../` counts from: the
    /// lexical parent of a path through a link may be another directory
    /// than its parent.
    canonical: Option<PathBuf>,
}

impl LockOrigins {
    /// Origins relative to `root`, the project directory that holds raeva.lock.
    ///
    /// `${project.basedir}` expands to the plain form of the canonical module
    /// directory, so that form comes first. The canonical form and the root as
    /// given cover a URL written by hand. A spelling none of them prefixes
    /// (another case on a case-insensitive volume, a `\\?\` path the plain
    /// form keeps) stays absolute: not portable, but never wrong.
    pub fn for_root(root: &Path) -> Self {
        let root = if root.as_os_str().is_empty() {
            Path::new(".")
        } else {
            root
        };
        let mut roots = Vec::new();
        let canonical = dunce::canonicalize(root).ok().map(|canonical| {
            let plain = plain_path(&canonical);
            roots.push(plain.clone());
            roots.push(canonical);
            plain
        });
        let absolute = if root.is_absolute() {
            Some(root.to_path_buf())
        } else {
            std::env::current_dir().ok().map(|cwd| cwd.join(root))
        };
        roots.extend(absolute);
        let mut seen = BTreeSet::new();
        roots.retain(|root| seen.insert(root.clone()));
        Self { roots, canonical }
    }

    /// Origins relative to the directory that holds the lockfile at `path`.
    pub(crate) fn for_lock_path(path: &Path) -> Self {
        Self::for_root(path.parent().unwrap_or_else(|| Path::new(".")))
    }

    /// The key a lock records for a repository declared with `url`, or `None`
    /// when `url` is not an absolute http, https or file URL, which no fetch
    /// could use and which therefore must not match any lock origin.
    pub fn declared(&self, url: &str) -> Option<String> {
        let parsed = Url::parse(url.trim()).ok()?;
        match parsed.scheme() {
            "http" | "https" => Some(normalize_repo_url(url)),
            "file" => Some(
                self.project_relative(&parsed)
                    .unwrap_or_else(|| normalize_repo_url(url)),
            ),
            _ => None,
        }
    }

    /// Whether the lock records `origin`, empty for none: a project-relative
    /// origin, or a URL some declaration could match ([`Self::declared`]).
    pub fn is_recordable(&self, origin: &str) -> bool {
        origin.is_empty()
            || validate_project_relative_origin(origin).is_ok()
            || self.declared(origin).is_some()
    }

    /// Whether the lock can record the origin of a repository declared
    /// with `url`, empty for none: [`Self::declared`] reads it. A relative
    /// path such as `./repo/`, which only a mirror can serve, cannot be
    /// recorded: it would read back as a project-relative origin.
    pub fn records_declaration(&self, url: &str) -> bool {
        url.is_empty() || self.declared(url).is_some()
    }

    /// [`Self::declared`], or the empty origin for a declaration whose URL the
    /// lock cannot record: a file only a mirror of it served is recorded
    /// with no origin ([`Lockfile::relativize_origins`](crate::Lockfile)).
    pub fn key(&self, url: &str) -> Option<String> {
        (self.declared(url)).or_else(|| (!url.trim().is_empty()).then(String::new))
    }

    /// The spelling the lock should record for an origin read from or about
    /// to be written to a lockfile. A project-relative origin is checked as
    /// written; a `file:` URL inside the project becomes one; anything else is
    /// returned unchanged.
    pub(crate) fn recorded(&self, value: &str) -> Result<String, LockError> {
        if is_project_relative_origin(value) {
            validate_project_relative_origin(value)?;
            return Ok(value.to_string());
        }
        if let Ok(parsed) = Url::parse(value.trim())
            && parsed.scheme() == "file"
            && let Some(token) = self.project_relative(&parsed)
        {
            return Ok(token);
        }
        Ok(value.to_string())
    }

    /// The `file:` URL of the directory that the project-relative origin
    /// `recorded` names; `None` for any other origin, for one that goes up
    /// past the project's last named directory, and for one naming a
    /// directory this OS cannot hold.
    pub fn project_url(&self, recorded: &str) -> Option<String> {
        validate_project_relative_origin(recorded).ok()?;
        let (levels, rest) = split_relative_origin(recorded)?;
        let mut directory = match levels {
            0 => self.roots.first()?.clone(),
            _ => self.canonical.clone()?,
        };
        for _ in 0..levels {
            directory.pop();
        }
        if levels > 0 && !is_named(&directory.components().collect::<Vec<_>>()) {
            return None;
        }
        for segment in rest.split('/').filter(|segment| !segment.is_empty()) {
            let name = decode_segment(segment)?;
            if cfg!(windows) && name.contains('\\') {
                return None;
            }
            directory.push(name);
        }
        let url = Url::from_directory_path(directory).ok()?;
        Some(url.to_string())
    }

    /// Whether a lock origin names the repository declared with `url`: the
    /// declaration's key ([`Self::key`]) equals the origin's. A declaration
    /// whose URL the lock cannot record matches only the empty origin, which
    /// stands for the one a mirror serves; no fetch could use its own URL.
    pub fn matches(&self, recorded: &str, url: &str) -> bool {
        self.key(url)
            .is_some_and(|key| key == recorded_key(recorded))
    }

    /// Two declared URLs that the lock would record as one project-relative
    /// origin although they name different directories, such as a path
    /// through a link that the origin's spelling does not show. Whichever
    /// declaration a later run picked could then read another directory than
    /// the one resolution used, so `raeva sync` refuses such a project.
    ///
    /// Spellings of one directory are not aliases: `file:///p/repo/`,
    /// `file://localhost/p/repo/`, and the `${project.basedir}/../repo/`
    /// that modules inherit from a parent all name `./repo/`.
    pub fn alias<'a>(&self, urls: impl IntoIterator<Item = &'a str>) -> Option<OriginAlias> {
        let mut seen: BTreeMap<String, (String, OriginIdentity)> = BTreeMap::new();
        for url in urls {
            let Some(key) = self.declared(url) else {
                continue;
            };
            if !is_project_relative_origin(&key) {
                continue;
            }
            let identity = origin_identity(url);
            let (first, first_identity) = seen
                .entry(key.clone())
                .or_insert_with(|| (url.to_string(), identity.clone()));
            if *first_identity != identity {
                return Some(OriginAlias {
                    origin: key,
                    first: first.clone(),
                    second: url.to_string(),
                });
            }
        }
        None
    }

    /// Pick the declaration a lock origin names, in the order `declarations`
    /// gives them. A project-relative origin that declarations with more than
    /// one distinct URL map to is ambiguous: their ids, policies and mirror
    /// selection may differ, so raeva does not guess between them.
    pub fn select<'a, T>(
        &self,
        recorded: &str,
        declarations: impl IntoIterator<Item = (&'a str, T)>,
    ) -> OriginSelection<T> {
        let mut first: Option<(OriginIdentity, T)> = None;
        for (url, declaration) in declarations {
            if !self.matches(recorded, url) {
                continue;
            }
            let identity = origin_identity(url);
            match &first {
                None => first = Some((identity, declaration)),
                Some((existing, _)) if *existing != identity => return OriginSelection::Ambiguous,
                Some(_) => {}
            }
        }
        first.map_or(OriginSelection::Undeclared, |(_, declaration)| {
            OriginSelection::Declared(declaration)
        })
    }

    /// The token for a parsed `file:` URL, if it has one: inside the project
    /// under any spelling of its root, outside it from the canonical root.
    /// `Url::parse` has already removed dot segments, as the fetch path does,
    /// so the token names the directory a read would open.
    fn project_relative(&self, url: &Url) -> Option<String> {
        let path = file_url_path(url)?;
        let inside =
            |path: &Path| (self.roots.iter()).find_map(|root| relative_origin(root, path, false));
        inside(&path).or_else(|| {
            // A path through a link, such as the shell's name for the
            // launcher's directory, is read where it leads, which `../`
            // counts to from the canonical root. A URL with a host names a
            // network share on Windows, which is not resolved.
            let resolved = match url.host() {
                None => dunce::canonicalize(&path).map_or(path, |path| plain_path(&path)),
                Some(_) => path,
            };
            inside(&resolved).or_else(|| relative_origin(self.canonical.as_ref()?, &resolved, true))
        })
    }
}

/// Two declarations [`LockOrigins::alias`] found: URLs, as declared, that
/// name different directories and that the lock would record as the one
/// project-relative `origin`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct OriginAlias {
    /// The project-relative origin both URLs map to.
    pub origin: String,
    /// The first URL that maps to it, as declared.
    pub first: String,
    /// A later URL that maps to it and names another directory.
    pub second: String,
}

/// What a declared repository URL names, for telling two declarations of one
/// lock origin apart: for a `file:` URL the directory, resolved through
/// links when it exists, and otherwise the normalized URL.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum OriginIdentity {
    Directory(PathBuf),
    Url(String),
}

pub(crate) fn origin_identity(url: &str) -> OriginIdentity {
    // `Url::parse` removes dot segments as the fetch path does, so this is
    // the directory a read would open. A URL with a host names a network
    // share on Windows; resolving it would reach the network even under
    // `--offline`, so it is compared as text.
    let directory = Url::parse(url.trim())
        .ok()
        .filter(|parsed| parsed.scheme() == "file" && parsed.host().is_none())
        .and_then(|parsed| file_url_path(&parsed));
    match directory {
        Some(path) => OriginIdentity::Directory(resolved_directory(&path)),
        None => OriginIdentity::Url(normalize_repo_url(url)),
    }
}

/// `path` with its deepest existing ancestor resolved through links, so a
/// directory that does not exist yet still compares equal under two
/// spellings of the project root.
fn resolved_directory(path: &Path) -> PathBuf {
    let mut rest = Vec::new();
    let mut current = path;
    loop {
        if let Ok(canonical) = dunce::canonicalize(current) {
            return rest
                .iter()
                .rev()
                .fold(canonical, |dir, name| dir.join(name));
        }
        match (current.parent(), current.file_name()) {
            (Some(parent), Some(name)) => {
                rest.push(name.to_os_string());
                current = parent;
            }
            _ => return path.to_path_buf(),
        }
    }
}

/// Outcome of [`LockOrigins::select`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OriginSelection<T> {
    /// The first declaration that names the origin.
    Declared(T),
    /// No declaration names the origin.
    Undeclared,
    /// Declarations that name different directories map to the origin.
    Ambiguous,
}

impl<T> OriginSelection<T> {
    /// The declaration, or `None` when the origin is undeclared or
    /// ambiguous.
    pub fn declared(self) -> Option<T> {
        match self {
            Self::Declared(declaration) => Some(declaration),
            Self::Undeclared | Self::Ambiguous => None,
        }
    }
}

/// Decode the [`LOCK_REPO_IDS_KEY`] block into an origin -> id map, strictly:
/// every line is `origin<TAB>id`, the origin non-empty, neither field holding
/// a tab or a carriage return, and no origin appears twice, because the
/// encoder never writes anything else.
pub(crate) fn decode_repo_id_lines(encoded: &str) -> Result<RepoIds, LockError> {
    let mut map = RepoIds::new();
    if encoded.is_empty() {
        return Ok(map);
    }
    for line in encoded.split('\n') {
        let malformed = || {
            LockError::Invalid(format!(
                "malformed {LOCK_REPO_IDS_KEY} entry {:?}: expected 'origin<TAB>id'",
                redact_origin(line.split('\t').next().unwrap_or_default())
            ))
        };
        let (origin, id) = line.split_once('\t').ok_or_else(malformed)?;
        if origin.is_empty() || !is_recordable_repo_id(origin) || !is_recordable_repo_id(id) {
            return Err(malformed());
        }
        if !map
            .entry(origin.to_string())
            .or_default()
            .insert(id.to_string())
        {
            return Err(LockError::Invalid(format!(
                "duplicate {LOCK_REPO_IDS_KEY} entry for {:?}",
                redact_origin(origin)
            )));
        }
    }
    Ok(map)
}

/// Whether `raeva.lock` can record `id` as a repository id, or any `repo_ids`
/// field: the line codec carries it unchanged and it is safe to print and to
/// write into `_remote.repositories`. A POM can declare an id holding a tab,
/// a line break or another control character; such an id is left
/// unrecorded, and export labels that repository as it does any repository
/// without a recorded id.
pub fn is_recordable_repo_id(id: &str) -> bool {
    rv_maven_types::is_terminal_safe(id)
}

/// Encode an origin -> ids map as the sorted `origin\tid` lines
/// [`decode_repo_id_lines`] reads, one per id. A field holding a tab or a
/// line break cannot be encoded and is refused rather than split into
/// another record. The ids only label `_remote.repositories`; they
/// authorize nothing.
pub(crate) fn encode_repo_id_lines(map: &RepoIds) -> Result<String, LockError> {
    let mut lines = Vec::with_capacity(map.len());
    for (origin, id) in map
        .iter()
        .flat_map(|(origin, ids)| ids.iter().map(move |id| (origin, id)))
    {
        if origin.is_empty() || !is_recordable_repo_id(origin) || !is_recordable_repo_id(id) {
            return Err(LockError::Invalid(format!(
                "repository {} has id {id:?}, which raeva.lock cannot record: \
                 a URL may not be empty, and neither may contain a control or invisible \
                 character",
                redact_origin(origin)
            )));
        }
        lines.push(format!("{origin}\t{id}"));
    }
    Ok(lines.join("\n"))
}

/// Convert a `repo_ids` map to recorded origins. Two URLs that become one
/// origin are aliases of one directory, which `raeva sync` refuses before
/// writing; their ids are kept together.
pub(crate) fn record_repo_ids(origins: &LockOrigins, ids: RepoIds) -> Result<RepoIds, LockError> {
    let mut recorded = RepoIds::new();
    for (origin, ids) in ids
        .into_iter()
        .filter(|(origin, _)| origins.is_recordable(origin))
    {
        recorded
            .entry(origins.recorded(&origin)?)
            .or_default()
            .extend(ids);
    }
    Ok(recorded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_origins_use_the_parsed_scheme() {
        for url in [
            "http://repo.example/maven2/",
            r"http://repo.example\@localhost/maven2/",
            " HTTPS://repo.example/ ",
            "http:repo.example/maven2/",
            r"https:\repo.example\maven2\",
            "h\tttp://repo.example/",
        ] {
            assert!(is_http_origin(url), "{url}");
        }
        for url in [
            "http://[invalid]/",
            "http://localhost:invalid/",
            "file:///repo/",
            "not a URL",
        ] {
            assert!(!is_http_origin(url), "{url}");
        }
    }

    fn origins(root: &Path) -> LockOrigins {
        LockOrigins::for_root(root)
    }

    fn file_url(path: &Path) -> String {
        Url::from_directory_path(path).unwrap().to_string()
    }

    /// A `file:` URL is normalized from its text alone, as a fetch reads
    /// it: a drive path with native separators, as `${project.basedir}`
    /// spells one on Windows, matches its URL spelling, and the result does
    /// not depend on whether the directory exists or is a link.
    #[test]
    fn file_urls_normalize_from_their_text() {
        assert_eq!(
            normalize_repo_url(r"file://C:\proj\x/repository"),
            normalize_repo_url("file:///C:/proj/x/repository/")
        );
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        let spelled = file_url(&dir.path().join("x")) + "../repo";
        let before = normalize_repo_url(&spelled);
        assert_eq!(before, file_url(&repo));
        std::fs::create_dir(&repo).unwrap();
        assert_eq!(normalize_repo_url(&spelled), before);
        #[cfg(unix)]
        {
            let link = dir.path().join("link");
            std::os::unix::fs::symlink(&repo, &link).unwrap();
            assert_eq!(normalize_repo_url(&file_url(&link)), file_url(&link));
        }
    }

    #[test]
    fn origins_are_redacted_as_urls() {
        assert_eq!(redact_origin("./repo/"), "./repo/");
        assert_eq!(redact_origin("./"), "./");
        assert_eq!(
            redact_origin("https://user:secret@repo.example/m2/?token=t#frag"),
            "https://repo.example/m2/?***"
        );
        assert_eq!(redact_origin("file:///srv/m2/"), "file:///srv/m2/");
        assert_eq!(redact_origin("./a/../b/"), rv_config::UNPARSABLE_URL);
        assert_eq!(
            redact_origin(".user:secret@host/"),
            rv_config::UNPARSABLE_URL
        );
        assert_eq!(redact_origin("secret-token"), rv_config::UNPARSABLE_URL);
        assert_eq!(
            redact_origin("alice:/s3cret@repo.example/m2"),
            rv_config::UNPARSABLE_URL
        );
    }

    /// A `file:` repository inside the project is recorded as the token for
    /// the directory a read would open; anything else keeps its spelling,
    /// and a declaration no fetch could use matches nothing.
    #[test]
    fn declarations_map_to_the_origin_the_lock_records() {
        let temp = tempfile::tempdir().unwrap();
        let root = dunce::canonicalize(temp.path()).unwrap();
        let project = root.join("project");
        std::fs::create_dir(&project).unwrap();
        let origins = origins(&project);
        let base = file_url(&project);
        let escaping = format!("{base}../outside/");
        let percent = file_url(&project.join("a%b"));
        for (url, recorded) in [
            (base.clone(), "./".to_string()),
            (
                file_url(&project.join("repo").join("nested")),
                "./repo/nested/".into(),
            ),
            (format!("{base}sub/../repo/"), "./repo/".into()),
            (format!("{base}sub/%2e%2e/repo/"), "./repo/".into()),
            // `to_file_path` decodes `%2F` into a separator, and so does the read.
            (format!("{base}a%2Fb/"), "./a/b/".into()),
            (file_url(&project.join("my repo")), "./my%20repo/".into()),
            (file_url(&project.join("a#b?")), "./a%23b%3F/".into()),
            (
                file_url(&project.join("a\u{200b}b")),
                "./a%E2%80%8Bb/".into(),
            ),
            (percent, "./a%25b/".into()),
            (escaping, "../outside/".into()),
            (
                "https://repo.example/m2".into(),
                "https://repo.example/m2/".into(),
            ),
        ] {
            assert_eq!(origins.declared(&url), Some(recorded), "{url}");
        }
        let sibling = file_url(&root.join("project-other"));
        assert_eq!(origins.recorded(&sibling).unwrap(), "../project-other/");
        assert_eq!(origins.recorded("").unwrap(), "");
        for unusable in ["./repo/", "repo", "ftp://files.example/m2/"] {
            assert_eq!(origins.declared(unusable), None);
        }
        assert!(!origins.matches("./repo/", "./repo/"));
        let share = "file://server/share/repo/";
        let as_text = OriginIdentity::Url(normalize_repo_url(share));
        assert_eq!(origin_identity(share), as_text, "a network share");
        let path = |url: &str| file_url_path(&Url::parse(url).unwrap());
        for unusable in [
            "file://server/",
            "file://${settings.repo}/",
            "file://server/%2Fshare/",
            "file://server/%5cshare/",
        ] {
            assert_eq!(path(unusable), None, "{unusable}");
        }
        if cfg!(windows) {
            assert_eq!(path("file:///C:"), None);
            assert_eq!(path("file:///C:/"), Some(PathBuf::from(r"C:\")));
            let share = Some(PathBuf::from(r"\\server\share\a"));
            assert_eq!(path("file://server/share/a"), share);
        }
    }

    /// A project-relative origin reads back as the directory it names,
    /// which the lock records as that origin again; nothing else does.
    #[test]
    fn a_project_relative_origin_names_its_directory() {
        let temp = tempfile::tempdir().unwrap();
        let root = dunce::canonicalize(temp.path()).unwrap();
        let origins = origins(&root);
        let url = origins.project_url("./repo/nested/").unwrap();
        assert_eq!(url, file_url(&root.join("repo").join("nested")));
        assert!(origins.matches("./repo/nested/", &url));
        for other in [
            "./../outside/",
            "./a%2Fb/",
            "https://repo.example/",
            "file:///repo/",
        ] {
            assert_eq!(origins.project_url(other), None, "{other}");
        }
    }

    /// A directory outside the project that shares a named directory with
    /// it is recorded from the canonical root with `../`, and its origin
    /// reads back as that directory; one sharing only the filesystem root
    /// keeps its URL. A spelling through a link counts from the canonical
    /// root too, whose parent is the directory's parent.
    #[test]
    fn a_directory_beside_the_project_is_recorded_from_the_directory_both_share() {
        let temp = tempfile::tempdir().unwrap();
        let base = dunce::canonicalize(temp.path()).unwrap();
        let project = base.join("a").join("project");
        std::fs::create_dir_all(&project).unwrap();
        let origins = origins(&project);
        let mut cases = vec![
            (base.join("a").join("x"), "../x/"),
            (base.join("b").join("y"), "../../b/y/"),
            (base.clone(), "../../"),
            (base.join("a").join("p%q"), "../p%25q/"),
        ];
        if cfg!(unix) {
            cases.push((base.join("a").join(r"p\q"), "../p%5Cq/"));
        }
        for (directory, token) in cases {
            let url = file_url(&directory);
            assert_eq!(origins.declared(&url).as_deref(), Some(token), "{url}");
            let read = origins.project_url(token).expect(token);
            assert_eq!(read, url, "{token}");
            assert!(origins.matches(token, &url), "{token}");
        }
        let top = file_url(&PathBuf::from(if cfg!(windows) { r"C:\" } else { "/" }));
        let apart = format!("{top}raeva-nowhere/repo/");
        if !base.starts_with(file_url_path(&Url::parse(&apart).unwrap()).unwrap()) {
            assert_eq!(origins.declared(&apart), Some(apart.clone()));
            assert_eq!(origins.recorded(&apart).unwrap(), apart);
        }
        let named = project
            .components()
            .filter(|component| matches!(component, Component::Normal(_)))
            .count();
        assert!(origins.project_url(&"../".repeat(named)).is_none());
        assert!(origins.project_url(&"../".repeat(named - 1)).is_some());
        assert_eq!(
            origins.project_url("../p%5Cq/").is_none(),
            cfg!(windows),
            "a name Windows cannot hold"
        );
        let missing = LockOrigins::for_root(&base.join("missing"));
        let sibling = file_url(&base.join("sibling"));
        assert_eq!(missing.declared(&sibling), Some(sibling));
        assert_eq!(missing.project_url("../sibling/"), None);

        #[cfg(unix)]
        {
            let link = base.join("link");
            std::os::unix::fs::symlink(&project, &link).unwrap();
            let linked = LockOrigins::for_root(&link);
            let through = format!("{}../x/", file_url(&link));
            assert_eq!(linked.declared(&through).as_deref(), Some("../../x/"));
            let read = linked.project_url("../../x/").unwrap();
            assert_eq!(read, file_url(&base.join("x")));
            assert_eq!(linked.declared(&read).as_deref(), Some("../../x/"));
            assert_eq!(
                linked.project_url("../x/").unwrap(),
                file_url(&base.join("a/x"))
            );
        }
    }

    #[test]
    fn token_validation_reads_the_text_as_written() {
        for valid in [
            "./",
            "./repo/",
            "./a/b%20c/",
            "./ünïcode/",
            "../",
            "../../a/b/",
            "./a%25b/",
            "../a%5Cb/",
            "../.../",
        ] {
            validate_project_relative_origin(valid).unwrap();
        }
        for invalid in [
            ".",
            "./repo",
            "./../outside/",
            "./a/../b/",
            "./a//b/",
            "./a/./b/",
            ".//",
            "./a\\b/",
            "./c:/",
            "./a%2e/",
            "./a/b c/",
            "./a#b/",
            "./a%41/",
            "./a%E2%80/",
            "./a%5c/",
            "./a%2F/",
            "./a%/",
            "./a%2/",
            "../a/../b/",
            "../..",
            "..//",
            "../a",
            ".././",
            "./../",
            "..",
            "...//",
            "./a\tb/",
            " ./repo/",
            ".repo/",
        ] {
            assert!(
                validate_project_relative_origin(invalid).is_err(),
                "{invalid:?} must be refused"
            );
        }
        let origins = origins(Path::new("."));
        assert!(origins.recorded(" ./../outside/ ").is_err());
        assert!(origins.recorded(".").is_err());
    }

    /// Spellings of one directory are one origin, also when the directory
    /// does not exist yet or the URL goes up and back down; the first
    /// declared spelling is selected and repo ids must agree across them.
    #[test]
    fn spellings_of_one_project_directory_are_one_origin() {
        let temp = tempfile::tempdir().unwrap();
        let root = dunce::canonicalize(temp.path()).unwrap();
        let origins = origins(&root);
        let plain = file_url(&root.join("repo"));
        let localhost = plain.replacen("file:///", "file://localhost/", 1);
        let dotted = file_url(&root.join("sub").join("..").join("repo"));
        let other = file_url(&root.join("other"));
        assert_eq!(origins.declared(&localhost).as_deref(), Some("./repo/"));
        let spellings = [&plain, &other, &localhost, &dotted, &plain];
        assert_eq!(origins.alias(spellings.map(String::as_str)), None);
        for second in [&plain, &localhost] {
            assert_eq!(
                origins.select("./repo/", [(plain.as_str(), 1), (second.as_str(), 2)]),
                OriginSelection::Declared(1)
            );
        }
        assert_eq!(
            origins.select("./other/", [(plain.as_str(), 1)]),
            OriginSelection::Undeclared
        );

        let set = |ids: &[&str]| ids.iter().map(ToString::to_string).collect::<BTreeSet<_>>();
        let ids = RepoIds::from([
            (plain.clone(), set(&["a"])),
            (localhost.clone(), set(&["b"])),
            ("https://repo.example/".to_string(), set(&["r"])),
        ]);
        let recorded = record_repo_ids(&origins, ids).unwrap();
        assert_eq!(recorded["./repo/"], set(&["a", "b"]));
        assert_eq!(recorded["https://repo.example/"], set(&["r"]));
        assert_eq!(recorded.len(), 2);

        // Two roots that are different directories stand in for a link the
        // origin's spelling hides: one token, two directories.
        let elsewhere = tempfile::tempdir().unwrap();
        let elsewhere = dunce::canonicalize(elsewhere.path()).unwrap();
        let two_roots = LockOrigins {
            roots: vec![root.clone(), elsewhere.clone()],
            canonical: None,
        };
        let there = file_url(&elsewhere.join("repo"));
        let alias = two_roots
            .alias([plain.as_str(), localhost.as_str(), there.as_str()])
            .expect("alias");
        assert_eq!(alias.origin, "./repo/");
        assert_eq!((alias.first, alias.second), (plain.clone(), there.clone()));
        assert_eq!(
            two_roots.select("./repo/", [(plain.as_str(), 1), (there.as_str(), 2)]),
            OriginSelection::Ambiguous
        );
    }

    #[test]
    fn repo_id_lines_decode_strictly() {
        let lines = "./repo/\tlocal\nhttps://r.example/\tr\nhttps://r.example/\ts";
        let decoded = decode_repo_id_lines(lines).unwrap();
        assert_eq!(decoded["https://r.example/"].len(), 2);
        assert_eq!(encode_repo_id_lines(&decoded).unwrap(), lines);
        assert!(decode_repo_id_lines("").unwrap().is_empty());
        assert!(decode_repo_id_lines("r\t").unwrap()["r"].contains(""));
        let malformed = [
            "no-tab",
            "a\tx\na\tx",
            "a\tx\ty",
            "a\tx\r",
            "\tx",
            "a\tx\n",
            "a\tx\n\nb\ty",
        ];
        for malformed in malformed {
            assert!(decode_repo_id_lines(malformed).is_err(), "{malformed:?}");
        }
        for (origin, id) in [("r", "x\ny"), ("r", "x\ty"), ("r", "x\ry"), ("", "x")] {
            let map = RepoIds::from([(origin.to_string(), BTreeSet::from([id.to_string()]))]);
            assert!(encode_repo_id_lines(&map).is_err(), "{id:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_project_root_matches_its_canonical_spelling() {
        let temp = tempfile::tempdir().unwrap();
        let real = dunce::canonicalize(temp.path()).unwrap().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = temp.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let origins = origins(&link);
        assert_eq!(
            origins.declared(&file_url(&real.join("repo"))).as_deref(),
            Some("./repo/")
        );
        assert_eq!(
            origins.declared(&file_url(&link.join("repo"))).as_deref(),
            Some("./repo/")
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_spellings_of_a_project_path_share_one_token() {
        let temp = tempfile::tempdir().unwrap();
        let root = plain_path(&dunce::canonicalize(temp.path()).unwrap());
        let origins = origins(&root);
        let text = root.display().to_string();
        // `${project.basedir}` interpolates the plain path with backslashes.
        let backslashed = format!("file://{text}/repo/");
        let forward = format!("file:///{}/repo/", text.replace('\\', "/"));
        let lower_drive = {
            let mut chars: Vec<char> = forward.chars().collect();
            chars[8] = chars[8].to_ascii_lowercase();
            chars.into_iter().collect::<String>()
        };
        for url in [&backslashed, &forward, &lower_drive] {
            assert_eq!(origins.declared(url).as_deref(), Some("./repo/"), "{url}");
        }
    }
}
