use std::sync::LazyLock;
use std::time::Duration;

use regex::Regex;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::error::Result;
use rv_config::UpdatePolicy;

/// A configured Maven-compatible artifact repository with URL and release/snapshot policies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Repository {
    pub id: Option<String>,
    pub url: String,
    pub releases_enabled: bool,
    pub snapshots_enabled: bool,
    #[serde(default, skip_serializing_if = "is_default_update_policy")]
    pub snapshots_update_policy: UpdatePolicy,
    /// Update policy for release artifacts. Defaults to `daily` to match
    /// Maven's `<releases><updatePolicy>daily</updatePolicy></releases>`.
    #[serde(
        default = "default_release_update_policy",
        skip_serializing_if = "is_default_release_policy"
    )]
    pub releases_update_policy: UpdatePolicy,
}

impl Repository {
    pub fn new(
        id: Option<String>,
        url: impl Into<String>,
        releases_enabled: bool,
        snapshots_enabled: bool,
    ) -> Self {
        let url = normalize_url(url.into());
        Self {
            id,
            url,
            releases_enabled,
            snapshots_enabled,
            snapshots_update_policy: UpdatePolicy::default(),
            releases_update_policy: default_release_update_policy(),
        }
    }

    pub(crate) fn from_config(config: &rv_config::RepoConfig) -> Self {
        Self::new(
            config.id.clone(),
            config.url.clone(),
            config.releases.unwrap_or(true),
            config.snapshots.unwrap_or(false),
        )
        .with_snapshot_policy(config.snapshots_update_policy.unwrap_or_default())
    }

    pub(crate) fn from_maven_repo(repo: &rv_maven_model::Repository) -> Self {
        let mut out = Self::new(
            repo.id.clone(),
            repo.url.clone(),
            repo.releases_enabled,
            repo.snapshots_enabled,
        );
        if let Some(policy) = repo
            .snapshots_update_policy
            .as_deref()
            .and_then(UpdatePolicy::parse)
        {
            out.snapshots_update_policy = policy;
        }
        if let Some(policy) = repo
            .releases_update_policy
            .as_deref()
            .and_then(UpdatePolicy::parse)
        {
            out.releases_update_policy = policy;
        }
        out
    }

    /// Returns true if this repository's release/snapshot policy allows the given version.
    pub fn allows_version(&self, version: &str) -> bool {
        if is_snapshot_version(version) {
            self.snapshots_enabled
        } else {
            self.releases_enabled
        }
    }

    pub fn base_url(&self) -> Result<Url> {
        Ok(Url::parse(&self.url)?)
    }

    pub fn url_for_path(&self, path: &str) -> Result<Url> {
        let base = self.base_url()?;
        let trimmed = path.trim_start_matches('/');

        // Reject a parent-directory segment up front. `Url::join` collapses
        // `..` per RFC 3986, so an unsanitized `..` in a (server-derived)
        // path could climb above the repository root while staying on the
        // same host, which the origin check below would not catch.
        if has_parent_dir_segment(trimmed) {
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
        // repository's own base directory. Catches any residual climb the
        // segment check above might miss while still on the same host.
        let base_dir = base_directory(base.path());
        if !joined.path().starts_with(&base_dir) {
            return Err(crate::error::RepoError::InvalidCoord(format!(
                "artifact path '{path}' escapes the repository base path '{base_dir}'"
            )));
        }

        Ok(joined)
    }

    pub(crate) fn with_snapshot_policy(mut self, policy: UpdatePolicy) -> Self {
        self.snapshots_update_policy = policy;
        self
    }

    /// Returns the configured update policy for a version of the given kind.
    pub fn update_policy_for(&self, version: &str) -> UpdatePolicy {
        if is_snapshot_version(version) {
            self.snapshots_update_policy
        } else {
            self.releases_update_policy
        }
    }

    /// Cache TTL implied by the repository's update policy for the given
    /// version. `always` collapses to zero (forcing a refetch), `never`
    /// returns a year (effectively no expiry), and `daily` / `interval:N`
    /// pass through their declared durations.
    pub fn update_policy_ttl(&self, version: &str) -> Duration {
        update_policy_to_duration(self.update_policy_for(version))
    }
}

fn update_policy_to_duration(policy: UpdatePolicy) -> Duration {
    match policy {
        UpdatePolicy::Always => Duration::from_secs(0),
        UpdatePolicy::Daily => Duration::from_secs(24 * 60 * 60),
        UpdatePolicy::Interval(minutes) => Duration::from_secs(u64::from(minutes) * 60),
        // `never` caps at one year so the cache still ages out eventually.
        // Treating it as i64::MAX (the policy's own sentinel) overflows when
        // converted to Duration arithmetic downstream.
        UpdatePolicy::Never => Duration::from_secs(365 * 24 * 60 * 60),
    }
}

impl From<rv_config::RepoConfig> for Repository {
    fn from(config: rv_config::RepoConfig) -> Self {
        Self::from_config(&config)
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

/// Normalizes a repository URL to a trailing-slash form.
///
/// Trims whitespace and appends a trailing slash if one is not already
/// present, so URL comparison and path joining stay consistent.
pub fn normalize_repo_url(url: &str) -> String {
    let trimmed = url.trim();
    if trimmed.ends_with('/') {
        trimmed.to_string()
    } else {
        format!("{trimmed}/")
    }
}

fn normalize_url(url: String) -> String {
    normalize_repo_url(&url)
}

fn is_default_update_policy(policy: &UpdatePolicy) -> bool {
    *policy == UpdatePolicy::default()
}

fn default_release_update_policy() -> UpdatePolicy {
    UpdatePolicy::Daily
}

fn is_default_release_policy(policy: &UpdatePolicy) -> bool {
    *policy == default_release_update_policy()
}

pub fn is_snapshot_version(version: &str) -> bool {
    static TIMESTAMP_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"-\d{8}\.\d{6}-\d+$").expect("snapshot timestamp regex must compile")
    });
    version.ends_with("-SNAPSHOT") || TIMESTAMP_RE.is_match(version)
}

/// True if any `/`-delimited segment of `path` is a parent-directory
/// reference (`..`), including the percent-encoded spellings (`%2e%2e`,
/// `.%2e`, …) that `Url::join` would otherwise still collapse.
fn has_parent_dir_segment(path: &str) -> bool {
    path.split('/').any(|seg| {
        let decoded = seg.replace("%2e", ".").replace("%2E", ".");
        decoded == ".."
    })
}

/// The directory portion of a URL path: everything up to and including the
/// final `/`. Used to verify a joined artifact URL stays under the
/// repository's base directory.
fn base_directory(path: &str) -> String {
    match path.rfind('/') {
        Some(idx) => path[..=idx].to_string(),
        None => "/".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::{Repository, is_snapshot_version};

    #[test]
    fn normalizes_url_trailing_slash() {
        let repo = Repository::new(
            Some("central".to_string()),
            "https://repo1.maven.org/maven2",
            true,
            false,
        );
        assert!(repo.url.ends_with('/'));
    }

    #[test]
    fn builds_joined_url() {
        let repo = Repository::new(
            Some("central".to_string()),
            "https://repo1.maven.org/maven2",
            true,
            false,
        );
        let url = repo
            .url_for_path("com/example/lib/1.0/lib-1.0.jar")
            .unwrap();
        assert!(url.as_str().contains("com/example/lib/1.0"));
    }

    #[test]
    fn detects_snapshot_version() {
        assert!(is_snapshot_version("1.0-SNAPSHOT"));
        assert!(is_snapshot_version("2.0.0-SNAPSHOT"));
        assert!(is_snapshot_version("1.0.0-beta-SNAPSHOT"));
        assert!(is_snapshot_version("1.0-20231115.123456-1"));
        assert!(!is_snapshot_version("1.0"));
        assert!(!is_snapshot_version("1.0.0"));
        assert!(!is_snapshot_version("1.0-beta"));
        assert!(!is_snapshot_version("SNAPSHOT"));
    }

    #[test]
    fn repo_allows_release_version_when_releases_enabled() {
        let repo = Repository::new(
            Some("central".to_string()),
            "https://repo1.maven.org/maven2",
            true,
            false,
        );
        assert!(repo.allows_version("1.0.0"));
        assert!(repo.allows_version("2.5.3"));
    }

    #[test]
    fn repo_rejects_snapshot_version_when_snapshots_disabled() {
        let repo = Repository::new(
            Some("central".to_string()),
            "https://repo1.maven.org/maven2",
            true,
            false,
        );
        assert!(!repo.allows_version("1.0-SNAPSHOT"));
        assert!(!repo.allows_version("2.0.0-SNAPSHOT"));
    }

    #[test]
    fn repo_allows_snapshot_version_when_snapshots_enabled() {
        let repo = Repository::new(
            Some("snapshots".to_string()),
            "https://repo.example/snapshots",
            false,
            true,
        );
        assert!(repo.allows_version("1.0-SNAPSHOT"));
        assert!(repo.allows_version("2.0.0-SNAPSHOT"));
    }

    #[test]
    fn repo_rejects_release_version_when_releases_disabled() {
        let repo = Repository::new(
            Some("snapshots".to_string()),
            "https://repo.example/snapshots",
            false,
            true,
        );
        assert!(!repo.allows_version("1.0.0"));
        assert!(!repo.allows_version("2.5.3"));
    }

    #[test]
    fn repo_allows_both_when_both_enabled() {
        let repo = Repository::new(
            Some("mixed".to_string()),
            "https://repo.example/all",
            true,
            true,
        );
        assert!(repo.allows_version("1.0.0"));
        assert!(repo.allows_version("1.0-SNAPSHOT"));
    }

    #[test]
    fn url_for_path_strips_leading_slashes() {
        let repo = Repository::new(
            Some("central".to_string()),
            "https://repo1.maven.org/maven2",
            true,
            false,
        );
        // Double-slash would be a protocol-relative URL attack, but
        // trim_start_matches('/') neutralizes it; the result stays on the original host.
        let result = repo.url_for_path("//evil.com/malicious-artifact.jar");
        let url = result.expect("leading slashes are stripped, path is safe");
        assert_eq!(url.host_str(), Some("repo1.maven.org"));
    }

    #[test]
    fn url_for_path_rejects_scheme_change() {
        let repo = Repository::new(
            Some("central".to_string()),
            "https://repo1.maven.org/maven2",
            true,
            false,
        );
        repo.url_for_path("http://evil.com/artifact.jar")
            .expect_err("scheme change must be rejected");
    }

    #[test]
    fn url_for_path_rejects_parent_dir_traversal() {
        let repo = Repository::new(
            Some("central".to_string()),
            "https://repo1.maven.org/maven2",
            true,
            false,
        );
        // A server-controlled snapshot value spliced into the filename could
        // carry `..` segments that Url::join collapses into a same-host climb
        // above the repository root.
        repo.url_for_path("com/example/lib/1.0/lib-../../../../private/secret.jar")
            .expect_err("'..' traversal must be rejected");
        repo.url_for_path("../../../../etc/passwd")
            .expect_err("leading '..' traversal must be rejected");
    }

    #[test]
    fn url_for_path_rejects_percent_encoded_traversal() {
        let repo = Repository::new(
            Some("central".to_string()),
            "https://repo1.maven.org/maven2",
            true,
            false,
        );
        repo.url_for_path("com/example/%2e%2e/%2e%2e/%2e%2e/secret.jar")
            .expect_err("percent-encoded '..' traversal must be rejected");
    }

    #[test]
    fn url_for_path_accepts_normal_artifact_path() {
        let repo = Repository::new(
            Some("central".to_string()),
            "https://repo1.maven.org/maven2",
            true,
            false,
        );
        let url = repo
            .url_for_path("org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.jar")
            .expect("a normal artifact path stays under the base directory");
        assert!(url.path().starts_with("/maven2/org/apache/commons/"));
    }
}
