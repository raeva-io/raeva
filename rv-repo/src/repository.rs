use rv_maven_types::is_snapshot_version;
use url::Url;

use crate::error::Result;
use crate::policy::Provenance;
use rv_config::{ChecksumPolicy, UpdatePolicy};

/// A configured Maven-compatible artifact repository with URL and release/snapshot policies.
///
/// Two repositories are equal when they describe the same endpoint and
/// policies; where each was declared ([`Repository::provenance`]) is not
/// compared.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Repository {
    /// The repository id, which selects credentials and mirrors and which
    /// Maven records in `_remote.repositories`.
    pub id: Option<String>,
    /// The base URL as declared, normalized with [`normalize_repo_url`].
    /// Not redacted; pass it through [`rv_config::redact_url`] before
    /// showing it.
    pub url: String,
    /// Whether release versions are fetched from it.
    pub releases_enabled: bool,
    /// Whether snapshot versions are fetched from it.
    pub snapshots_enabled: bool,
    /// How long cached snapshot metadata and `-SNAPSHOT` POMs stay fresh.
    /// Defaults to [`UpdatePolicy::default`], `daily`, as in Maven.
    pub snapshots_update_policy: UpdatePolicy,
    /// Update policy for release artifacts, with the same default.
    pub releases_update_policy: UpdatePolicy,
    /// What a checksum mismatch on remote release `maven-metadata.xml`
    /// does after one refetch: `fail` refuses it (and also refuses metadata
    /// without a sidecar), `warn` and `ignore` log and use it. POMs and
    /// artifacts are always verified.
    pub releases_checksum_policy: ChecksumPolicy,
    /// [`Repository::releases_checksum_policy`] for snapshot metadata.
    pub snapshots_checksum_policy: ChecksumPolicy,
    /// Where this repository was declared. Not compared.
    provenance: Uncompared<Provenance>,
    /// Whether a dependency's or imported BOM's POM declared it, and no
    /// mirror replaces it. Not compared.
    descriptor: Uncompared<bool>,
    /// The URL as declared, which Maven 3.10 hashes into a repository
    /// filter file's name and mirror patterns read. Not compared.
    declared_url: Uncompared<String>,
    /// The names a POM's model looked up to interpolate the URL
    /// ([`rv_maven_model::Repository::url_reads`]). Not compared.
    url_reads: Uncompared<Vec<String>>,
    /// [`Self::url_reads`] for the id. Not compared.
    id_reads: Uncompared<Vec<String>>,
    /// The `<layout>` once interpolated, `None` for `default`, which
    /// decides the mirror that serves it.
    layout: Option<String>,
    /// Why a POM's `<layout>` keeps raeva from reading it as Maven does
    /// ([`rv_maven_model::Repository::layout_refusal`]). Not compared.
    layout_refusal: Uncompared<Option<String>>,
}

#[derive(Debug, Clone, Copy, Default)]
struct Uncompared<T>(T);

impl<T> PartialEq for Uncompared<T> {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl<T> Eq for Uncompared<T> {}

/// How strongly a checksum policy refuses: `warn` and `ignore` accept,
/// `fail` refuses mismatching metadata, and an unsupported one refuses the
/// repository.
fn strictness(policy: ChecksumPolicy) -> u8 {
    match policy {
        ChecksumPolicy::Warn | ChecksumPolicy::Ignore => 0,
        ChecksumPolicy::Fail => 1,
        ChecksumPolicy::Unsupported => 2,
    }
}

impl Repository {
    /// A repository at `url` (normalized with [`normalize_repo_url`]) with
    /// the default update and checksum policies and
    /// [`Provenance::Caller`]. The URL is not parsed here; a bad one fails
    /// at the first request.
    pub fn new(
        id: Option<String>,
        url: impl Into<String>,
        releases_enabled: bool,
        snapshots_enabled: bool,
    ) -> Self {
        let url = url.into();
        Self {
            id,
            url: normalize_repo_url(&url),
            declared_url: Uncompared(url.trim().to_string()),
            releases_enabled,
            snapshots_enabled,
            snapshots_update_policy: UpdatePolicy::default(),
            releases_update_policy: UpdatePolicy::default(),
            releases_checksum_policy: ChecksumPolicy::default(),
            snapshots_checksum_policy: ChecksumPolicy::default(),
            provenance: Uncompared(Provenance::Caller),
            descriptor: Uncompared(false),
            url_reads: Uncompared(Vec::new()),
            id_reads: Uncompared(Vec::new()),
            layout: None,
            layout_refusal: Uncompared(None),
        }
    }

    /// Where this repository was declared, which decides what
    /// [`crate::RepositoryPolicy`] lets it do.
    pub fn provenance(&self) -> Provenance {
        self.provenance.0
    }

    pub(crate) fn set_provenance(&mut self, provenance: Provenance) {
        self.provenance.0 = provenance;
    }

    /// Whether a dependency's or imported BOM's POM declared it, and no
    /// mirror replaces it: what Maven's remote repository manager calls a
    /// descriptor repository.
    pub(crate) fn descriptor(&self) -> bool {
        self.descriptor.0
    }

    pub(crate) fn set_descriptor(&mut self, descriptor: bool) {
        self.descriptor.0 = descriptor;
    }

    /// The URL as declared, before [`normalize_repo_url`].
    pub fn declared_url(&self) -> &str {
        &self.declared_url.0
    }

    /// The names a POM's model looked up to interpolate the URL; none for a
    /// configured repository, whose URL is not interpolated.
    pub fn url_reads(&self) -> &[String] {
        &self.url_reads.0
    }

    /// [`Self::url_reads`] for the id.
    pub fn id_reads(&self) -> &[String] {
        &self.id_reads.0
    }

    /// The layout mirrors' `<mirrorOfLayouts>` match.
    pub fn layout(&self) -> &str {
        self.layout.as_deref().unwrap_or("default")
    }

    /// See [`rv_maven_model::Repository::layout_refusal`].
    pub fn layout_refusal(&self) -> Option<&str> {
        self.layout_refusal.0.as_deref()
    }

    /// Requests go to `url` instead, as through a mirror.
    pub(crate) fn set_url(&mut self, url: &str) {
        self.url = normalize_repo_url(url);
        self.declared_url.0 = url.trim().to_string();
    }

    /// [`Self::set_url`] for a mirror, which declares its URL as written.
    pub(crate) fn set_mirror_url(&mut self, mirror: &rv_config::MirrorConfig) {
        self.set_url(&mirror.url);
        if let Some(declared) = &mirror.declared_url {
            self.declared_url.0 = declared.trim().to_string();
        }
    }

    pub(crate) fn from_config(config: &rv_config::RepoConfig) -> Self {
        let declared = config.declared_url.as_deref().unwrap_or(&config.url);
        Self {
            declared_url: Uncompared(declared.trim().to_string()),
            snapshots_update_policy: config.snapshots_update_policy.unwrap_or_default(),
            releases_update_policy: config.releases_update_policy.unwrap_or_default(),
            releases_checksum_policy: config.releases_checksum_policy.unwrap_or_default(),
            snapshots_checksum_policy: config.snapshots_checksum_policy.unwrap_or_default(),
            provenance: Uncompared(Provenance::Configured),
            ..Self::new(
                config.id.clone(),
                config.url.clone(),
                config.releases.unwrap_or(true),
                config.snapshots.unwrap_or(false),
            )
        }
    }

    pub(crate) fn from_maven_repo(repo: &rv_maven_model::Repository) -> Self {
        let base = Self::new(
            repo.id.clone(),
            repo.url.clone(),
            repo.releases_enabled,
            repo.snapshots_enabled,
        );
        let update = |policy: &Option<String>, default| {
            policy
                .as_deref()
                .and_then(UpdatePolicy::parse)
                .unwrap_or(default)
        };
        let checksum = |policy: &Option<String>| {
            policy
                .as_deref()
                .map(ChecksumPolicy::from_maven)
                .unwrap_or_default()
        };
        Self {
            snapshots_update_policy: update(
                &repo.snapshots_update_policy,
                base.snapshots_update_policy,
            ),
            releases_update_policy: update(
                &repo.releases_update_policy,
                base.releases_update_policy,
            ),
            releases_checksum_policy: checksum(&repo.releases_checksum_policy),
            snapshots_checksum_policy: checksum(&repo.snapshots_checksum_policy),
            declared_url: Uncompared(
                (repo.declared_url.as_deref().unwrap_or(&repo.url))
                    .trim()
                    .to_string(),
            ),
            url_reads: Uncompared(repo.url_reads.clone()),
            id_reads: Uncompared(repo.id_reads.clone()),
            layout: repo.layout.clone().filter(|layout| layout != "default"),
            layout_refusal: Uncompared(repo.layout_refusal()),
            provenance: Uncompared(if repo.root_declared {
                Provenance::LocalPom
            } else {
                Provenance::FetchedPom
            }),
            ..base
        }
    }

    pub(crate) fn metadata_checksum_policy(&self, version: &str) -> ChecksumPolicy {
        if is_snapshot_version(version) {
            self.snapshots_checksum_policy
        } else {
            self.releases_checksum_policy
        }
    }

    /// Preserve explicit strictness when multiple declarations share a URL.
    /// Repository deduplication must never discard a POM's `fail` policy,
    /// nor a [`ChecksumPolicy::Unsupported`] one that refuses the
    /// repository. Maven keeps a declaration under another id as a separate
    /// repository, so its unsupported policy refuses only that one: here it
    /// counts as `fail`, and cannot refuse the repository kept.
    pub fn merge_checksum_policies(&mut self, other: &Self) {
        self.merge_policies(other, self.id == other.id);
    }

    /// [`Repository::merge_checksum_policies`] for a declaration in a POM
    /// fetched for a dependency. Maven keeps the repository it met first
    /// under an id and drops a later declaration with that id, so here an
    /// unsupported policy counts as `fail` whatever the id.
    pub fn merge_fetched_checksum_policies(&mut self, other: &Self) {
        self.merge_policies(other, false);
    }

    fn merge_policies(&mut self, other: &Self, keep_unsupported: bool) {
        let stricter = |mine: &mut ChecksumPolicy, theirs: ChecksumPolicy| {
            let theirs = match theirs {
                ChecksumPolicy::Unsupported if !keep_unsupported => ChecksumPolicy::Fail,
                theirs => theirs,
            };
            if strictness(theirs) > strictness(*mine) {
                *mine = theirs;
            }
        };
        stricter(
            &mut self.releases_checksum_policy,
            other.releases_checksum_policy,
        );
        stricter(
            &mut self.snapshots_checksum_policy,
            other.snapshots_checksum_policy,
        );
    }

    /// Whether either checksum policy is one that
    /// [`Repository::merge_checksum_policies`] keeps over the other
    /// declaration's.
    pub fn has_strict_checksum_policy(&self) -> bool {
        strictness(self.releases_checksum_policy) > 0
            || strictness(self.snapshots_checksum_policy) > 0
    }

    /// The repository as Maven reads its version listing: for a range or
    /// `LATEST` (`with_snapshots`) under every version kind it enables, with
    /// the least strict checksum policy and the most frequent update policy
    /// among them, and for `RELEASE` under the releases policies only.
    /// `None` when it enables no kind the listing reads. The repository
    /// returned reads the listing under its releases policies, which hold
    /// the merged ones.
    ///
    /// # Errors
    ///
    /// [`RepoError::Config`](crate::RepoError::Config) when the checksum
    /// policy of a kind the listing reads is unsupported, which makes Maven
    /// refuse the listing.
    pub fn version_listing(&self, with_snapshots: bool) -> Result<Option<Self>> {
        let snapshots = with_snapshots && self.snapshots_enabled;
        if !self.releases_enabled && !snapshots {
            return Ok(None);
        }
        for (read, policy, kind) in [
            (
                self.releases_enabled,
                self.releases_checksum_policy,
                "releases",
            ),
            (snapshots, self.snapshots_checksum_policy, "snapshots"),
        ] {
            if read && policy == ChecksumPolicy::Unsupported {
                return Err(unsupported_policy(self, kind));
            }
        }
        let mut listing = self.clone();
        if !self.releases_enabled {
            listing.releases_enabled = true;
            listing.releases_checksum_policy = self.snapshots_checksum_policy;
            listing.releases_update_policy = self.snapshots_update_policy;
        } else if snapshots {
            // Maven applies the more lenient policy, ignore before warn. Both
            // policies passed the unsupported check above.
            if matches!(
                (
                    self.snapshots_checksum_policy,
                    self.releases_checksum_policy
                ),
                (
                    ChecksumPolicy::Ignore,
                    ChecksumPolicy::Warn | ChecksumPolicy::Fail
                ) | (ChecksumPolicy::Warn, ChecksumPolicy::Fail)
            ) {
                listing.releases_checksum_policy = self.snapshots_checksum_policy;
            }
            if self.snapshots_update_policy.ttl_secs() < self.releases_update_policy.ttl_secs() {
                listing.releases_update_policy = self.snapshots_update_policy;
            }
        }
        Ok(Some(listing))
    }

    /// Returns true if this repository's release/snapshot policy allows the given version.
    pub fn allows_version(&self, version: &str) -> bool {
        if is_snapshot_version(version) {
            self.snapshots_enabled
        } else {
            self.releases_enabled
        }
    }

    /// Whether this repository's policy keeps `version` among the versions it
    /// lists for a range. Maven filters that listing with
    /// `ArtifactUtils.isSnapshot`, not maven-resolver's rule.
    pub fn allows_listed_version(&self, version: &str) -> bool {
        if rv_maven_types::is_listed_snapshot_version(version) {
            self.snapshots_enabled
        } else {
            self.releases_enabled
        }
    }

    /// True for a read-only `file://` repository on the local filesystem.
    pub fn is_local(&self) -> bool {
        self.base_url().is_ok_and(|url| url.scheme() == "file")
    }

    /// [`Repository::url`] parsed.
    ///
    /// # Errors
    ///
    /// [`RepoError::Url`](crate::RepoError::Url) when it does not parse.
    pub fn base_url(&self) -> Result<Url> {
        Ok(Url::parse(&self.url)?)
    }

    pub(crate) fn url_for_path(&self, path: &str) -> Result<Url> {
        let base = self.base_url()?;
        let trimmed = path.trim_start_matches('/');

        // Reject a parent-directory segment up front. `Url::join` collapses
        // `..` per RFC 3986, so an unsanitized `..` in a (server-derived)
        // path could climb above the repository root while staying on the
        // same host, which the origin check below would not catch. Percent-
        // encoded spellings (`%2e%2e`, `.%2e`, …) still count.
        if trimmed
            .split('/')
            .any(|seg| seg.replace("%2e", ".").replace("%2E", ".") == "..")
        {
            return Err(crate::error::RepoError::InvalidCoord(format!(
                "artifact path '{path}' contains a parent-directory ('..') segment"
            )));
        }

        let joined = base.join(trimmed)?;

        // SSRF protection: verify the joined URL still points to the same origin.
        // Url::join can produce a different host if the path contains absolute URL
        // references (e.g., "//evil.com/path" or "https://evil.com").
        if joined.scheme() != base.scheme()
            || joined.host() != base.host()
            || joined.port() != base.port()
        {
            return Err(crate::error::RepoError::InvalidCoord(format!(
                "artifact path '{}' would redirect to a different host (base: {}, result: {})",
                path,
                base.origin().ascii_serialization(),
                joined.origin().ascii_serialization(),
            )));
        }

        // Defense-in-depth: the resolved path must remain under the
        // repository's own base directory (everything up to and including the
        // final `/`). Catches any residual climb the segment check above
        // might miss while still on the same host.
        let base_path = base.path();
        let base_dir = base_path.rfind('/').map_or("/", |idx| &base_path[..=idx]);
        if !joined.path().starts_with(base_dir) {
            return Err(crate::error::RepoError::InvalidCoord(format!(
                "artifact path '{path}' escapes the repository base path '{base_dir}'"
            )));
        }

        Ok(joined)
    }

    pub(crate) fn update_policy_for(&self, version: &str) -> UpdatePolicy {
        if is_snapshot_version(version) {
            self.snapshots_update_policy
        } else {
            self.releases_update_policy
        }
    }

    /// How long a copy for `version` fetched now stays fresh.
    pub(crate) fn update_policy_expiry(&self, version: &str) -> rv_store::metadata_cache::Expiry {
        match self.update_policy_for(version) {
            UpdatePolicy::Daily => rv_store::metadata_cache::Expiry::Daily,
            policy => rv_store::metadata_cache::Expiry::After(policy.ttl_secs()),
        }
    }
}

/// Seconds a check made at `written` stays fresh under `policy`. Maven
/// decides `daily` anew at every read ([`rv_store::daily`]), so for it this
/// is 0 once the check is due now, in this run's zone, and `i64::MAX` until
/// then.
pub fn fresh_secs(policy: UpdatePolicy, written: &chrono::DateTime<chrono::Local>) -> i64 {
    match policy {
        UpdatePolicy::Daily => {
            let now = chrono::Local::now().timestamp();
            match rv_store::daily::due(written.timestamp(), now) {
                true => 0,
                false => i64::MAX,
            }
        }
        policy => policy.ttl_secs(),
    }
}

impl From<&rv_config::RepoConfig> for Repository {
    fn from(config: &rv_config::RepoConfig) -> Self {
        Self::from_config(config)
    }
}

impl From<rv_maven_model::Repository> for Repository {
    fn from(repo: rv_maven_model::Repository) -> Self {
        Self::from_maven_repo(&repo)
    }
}

impl From<&rv_maven_model::Repository> for Repository {
    fn from(repo: &rv_maven_model::Repository) -> Self {
        Self::from_maven_repo(repo)
    }
}

pub use rv_lock::normalize_repo_url;

/// The refusal of a download that an unsupported `kind` checksum policy of
/// `repo` covers.
pub(crate) fn unsupported_policy(repo: &Repository, kind: &str) -> crate::RepoError {
    crate::RepoError::Config(format!(
        "repository '{}' has a <{kind}><checksumPolicy> that is not fail, warn or ignore, so raeva \
         does not download from it",
        rv_maven_types::bounded(repo.id.as_deref().unwrap_or("repository"))
    ))
}

#[cfg(test)]
mod tests {
    use super::Repository;

    /// `never` does not expire, and `daily` is decided when read.
    #[test]
    fn never_does_not_expire_and_daily_is_decided_when_read() {
        use rv_store::metadata_cache::Expiry;
        let mut repo = Repository::new(None, "https://example.com/", true, true);
        repo.releases_update_policy = rv_config::UpdatePolicy::Never;
        assert_eq!(repo.update_policy_expiry("1.0"), Expiry::NEVER);
        repo.releases_update_policy = rv_config::UpdatePolicy::Daily;
        assert_eq!(repo.update_policy_expiry("1.0"), Expiry::Daily);
    }

    #[test]
    fn local_classification_uses_the_parsed_scheme() {
        for url in [
            "file:///repo/",
            "fi\tle:///repo/",
            "fi\nle:///repo/",
            "FI\rLE:///repo/",
        ] {
            assert!(Repository::new(None, url, true, true).is_local(), "{url:?}");
        }
        assert!(!Repository::new(None, "https://example.com/", true, true).is_local());
    }

    /// A range listing is filtered with Maven's `ArtifactUtils.isSnapshot`,
    /// which ignores case and needs a hyphen before a timestamp, while a
    /// request uses maven-resolver's rule.
    #[test]
    fn versions_follow_the_enabled_kinds() {
        // (releases, snapshots, version, requested, listed)
        #[rustfmt::skip]
        let cases = [
            (true, false, "2.5.3", true, true),
            (true, false, "1.0-SNAPSHOT", false, false),
            (true, false, "1.0-snapshot", true, false),
            (true, false, "20240101.010101-1", false, true),
            (false, true, "2.5.3", false, false),
            (false, true, "2.0.0-SNAPSHOT", true, true),
            (true, true, "1.0.0", true, true),
            (true, true, "1.0-SNAPSHOT", true, true),
        ];
        for (releases, snapshots, version, requested, listed) in cases {
            let repo = Repository::new(None, "https://repo.example/", releases, snapshots);
            assert_eq!(
                repo.allows_version(version),
                requested,
                "{version} {releases} {snapshots}"
            );
            assert_eq!(
                repo.allows_listed_version(version),
                listed,
                "{version} {releases} {snapshots}"
            );
        }
    }

    /// A server-controlled snapshot value spliced into a file name could
    /// carry `..` segments that `Url::join` collapses into a same-host
    /// climb above the repository root.
    #[test]
    fn url_for_path_stays_under_the_repository() {
        let repo = Repository::new(None, "https://repo1.maven.org/maven2", true, false);
        assert!(repo.url.ends_with('/'));
        for (path, expected) in [
            (
                "org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.jar",
                "https://repo1.maven.org/maven2/org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.jar",
            ),
            (
                "//evil.com/malicious-artifact.jar",
                "https://repo1.maven.org/maven2/evil.com/malicious-artifact.jar",
            ),
        ] {
            assert_eq!(repo.url_for_path(path).unwrap().as_str(), expected);
        }
        for path in [
            "http://evil.com/artifact.jar",
            "com/example/lib/1.0/lib-../../../../private/secret.jar",
            "../../../../etc/passwd",
            "com/example/%2e%2e/%2e%2e/%2e%2e/secret.jar",
        ] {
            repo.url_for_path(path).expect_err(path);
        }
    }

    /// Merging two declarations of one URL keeps the strictest checksum
    /// policy of each kind, an unsupported one above `fail`.
    #[test]
    fn merging_keeps_the_strictest_checksum_policy() {
        use rv_config::ChecksumPolicy;
        let mut first = Repository::new(None, "https://repo.example/", true, true);
        first.releases_checksum_policy = ChecksumPolicy::Fail;
        let mut second = first.clone();
        second.releases_checksum_policy = ChecksumPolicy::Unsupported;
        second.snapshots_checksum_policy = ChecksumPolicy::Ignore;
        assert!(second.has_strict_checksum_policy());
        first.merge_checksum_policies(&second);
        assert_eq!(first.releases_checksum_policy, ChecksumPolicy::Unsupported);
        assert_eq!(first.snapshots_checksum_policy, ChecksumPolicy::Warn);
        second.merge_checksum_policies(&Repository::new(None, "https://repo.example/", true, true));
        assert_eq!(second.releases_checksum_policy, ChecksumPolicy::Unsupported);

        // Under another id, an unsupported policy only tightens to `fail`.
        let mut configured = Repository::new(
            Some("configured".to_string()),
            "https://repo.example/",
            true,
            true,
        );
        let mut other = configured.clone();
        other.id = Some("other".to_string());
        other.releases_checksum_policy = ChecksumPolicy::Unsupported;
        configured.merge_checksum_policies(&other);
        assert_eq!(configured.releases_checksum_policy, ChecksumPolicy::Fail);
    }

    /// As Maven Resolver's `RepositoryPolicy()`, an omitted update policy is
    /// `daily` for snapshots too, so a range a repository serves both kinds
    /// for keeps its listing until midnight.
    #[test]
    fn an_omitted_update_policy_is_daily() {
        use rv_config::UpdatePolicy;

        let declared = rv_maven_model::Repository::new(Some("r"), "https://example.com/");
        let mut configured = rv_config::RepoConfig::new(Some("r"), "https://example.com/");
        configured.snapshots = Some(true);
        for repo in [
            Repository::new(None, "https://example.com/", true, true),
            Repository::from_maven_repo(&declared),
            Repository::from_config(&configured),
        ] {
            assert_eq!(repo.snapshots_update_policy, UpdatePolicy::Daily);
            assert_eq!(repo.releases_update_policy, UpdatePolicy::Daily);
            let range = repo.version_listing(true).unwrap().unwrap();
            assert_eq!(range.releases_update_policy, UpdatePolicy::Daily);
        }
    }

    #[test]
    fn version_listing_merges_the_policies_of_the_kinds_it_reads() {
        use rv_config::{ChecksumPolicy, UpdatePolicy};

        let mut repo = Repository::new(Some("r".into()), "https://example.com/", true, true);
        repo.releases_checksum_policy = ChecksumPolicy::Warn;
        repo.snapshots_checksum_policy = ChecksumPolicy::Fail;
        repo.releases_update_policy = UpdatePolicy::Never;
        repo.snapshots_update_policy = UpdatePolicy::Always;

        let range = repo.version_listing(true).unwrap().unwrap();
        assert_eq!(range.releases_checksum_policy, ChecksumPolicy::Warn);
        assert_eq!(range.releases_update_policy, UpdatePolicy::Always);
        let release = repo.version_listing(false).unwrap().unwrap();
        assert_eq!(release.releases_checksum_policy, ChecksumPolicy::Warn);
        assert_eq!(release.releases_update_policy, UpdatePolicy::Never);

        repo.releases_enabled = false;
        assert!(repo.version_listing(false).unwrap().is_none());
        let snapshots_only = repo.version_listing(true).unwrap().unwrap();
        assert!(snapshots_only.releases_enabled);
        assert_eq!(
            snapshots_only.releases_checksum_policy,
            ChecksumPolicy::Fail
        );

        repo.releases_enabled = true;
        repo.releases_checksum_policy = ChecksumPolicy::Fail;
        repo.snapshots_checksum_policy = ChecksumPolicy::Ignore;
        let range = repo.version_listing(true).unwrap().unwrap();
        assert_eq!(range.releases_checksum_policy, ChecksumPolicy::Ignore);

        repo.releases_enabled = false;
        repo.snapshots_checksum_policy = ChecksumPolicy::Unsupported;
        assert!(repo.version_listing(true).is_err());
        repo.releases_enabled = true;
        assert!(repo.version_listing(false).is_ok());
    }
}
