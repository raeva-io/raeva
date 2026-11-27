//! Where the model service reads POMs and version metadata from.

use bytes::Bytes;
use futures::future::BoxFuture;
use rv_maven_types::Coord;
use rv_repo::{
    Admission, ArtifactRequest, Declaration, Metadata, RepoClient, RepoError, Repository,
    SnapshotResolution,
};

/// The repository reads model building needs: POMs, `maven-metadata.xml`
/// and snapshot versions, and the policy that admits the repositories POMs
/// declare. [`RepoPomSource`] reads them through a [`RepoClient`]; tests
/// serve them from memory.
pub(crate) trait PomSource: Send + Sync {
    fn admit(&self, repos: Vec<Repository>, from: Declaration) -> Admission;

    fn effective_repository(&self, repo: &Repository) -> Repository;

    /// Whether a request to `repo` would carry a credential.
    fn sends_credential(&self, _repo: &Repository) -> bool {
        false
    }

    fn pom<'a>(
        &'a self,
        repo: &'a Repository,
        request: &'a ArtifactRequest,
    ) -> BoxFuture<'a, Result<(Bytes, String), RepoError>>;

    /// Fetch the POM [`PomSource::pom`] would return for the same
    /// arguments ahead of that call, and return its bytes, `None` when the
    /// source does not prefetch it, or the error of the fetch. Nothing about
    /// the attempt reaches the later `pom` call but its bytes and a miss.
    fn prefetch_pom<'a>(
        &'a self,
        _repo: &'a Repository,
        _request: &'a ArtifactRequest,
    ) -> BoxFuture<'a, Result<Option<Bytes>, RepoError>> {
        Box::pin(async { Ok(None) })
    }

    fn metadata<'a>(
        &'a self,
        repo: &'a Repository,
        coord: &'a Coord,
    ) -> BoxFuture<'a, Result<Metadata, RepoError>>;

    /// Fetch the version list [`PomSource::metadata`] would return for the
    /// same arguments ahead of that call, or `None`, as
    /// [`PomSource::prefetch_pom`] does for a POM.
    fn prefetch_metadata<'a>(
        &'a self,
        _repo: &'a Repository,
        _coord: &'a Coord,
    ) -> BoxFuture<'a, Option<Metadata>> {
        Box::pin(async { None })
    }

    fn snapshot<'a>(
        &'a self,
        repo: &'a Repository,
        coord: &'a Coord,
    ) -> BoxFuture<'a, Result<SnapshotResolution, RepoError>>;
}

pub(crate) struct RepoPomSource(pub(crate) RepoClient);

impl PomSource for RepoPomSource {
    fn admit(&self, repos: Vec<Repository>, from: Declaration) -> Admission {
        self.0.policy().admit(repos, from)
    }

    fn effective_repository(&self, repo: &Repository) -> Repository {
        self.0.effective_repository(repo)
    }

    fn sends_credential(&self, repo: &Repository) -> bool {
        self.0.sends_credential(repo)
    }

    fn pom<'a>(
        &'a self,
        repo: &'a Repository,
        request: &'a ArtifactRequest,
    ) -> BoxFuture<'a, Result<(Bytes, String), RepoError>> {
        Box::pin(self.0.fetch_pom_with_path(repo, request))
    }

    fn prefetch_pom<'a>(
        &'a self,
        repo: &'a Repository,
        request: &'a ArtifactRequest,
    ) -> BoxFuture<'a, Result<Option<Bytes>, RepoError>> {
        Box::pin(self.0.prefetch_pom(repo, request))
    }

    fn metadata<'a>(
        &'a self,
        repo: &'a Repository,
        coord: &'a Coord,
    ) -> BoxFuture<'a, Result<Metadata, RepoError>> {
        Box::pin(self.0.fetch_metadata(repo, coord))
    }

    fn prefetch_metadata<'a>(
        &'a self,
        repo: &'a Repository,
        coord: &'a Coord,
    ) -> BoxFuture<'a, Option<Metadata>> {
        Box::pin(self.0.prefetch_metadata(repo, coord))
    }

    fn snapshot<'a>(
        &'a self,
        repo: &'a Repository,
        coord: &'a Coord,
    ) -> BoxFuture<'a, Result<SnapshotResolution, RepoError>> {
        Box::pin(self.0.resolve_snapshot_version(repo, coord))
    }
}

#[cfg(test)]
pub(crate) use memory::MemoryPomSource;

#[cfg(test)]
mod memory {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use super::*;
    use rv_config::SecurityConfig;
    use rv_repo::RepositoryPolicy;

    /// Repository files served from memory by repository URL and path, with
    /// every request recorded.
    #[derive(Default)]
    pub(crate) struct MemoryPomSource {
        security: SecurityConfig,
        files: HashMap<(String, String), Bytes>,
        refusals: HashMap<String, reqwest::StatusCode>,
        delays: HashMap<String, std::time::Duration>,
        credentialed: Vec<String>,
        prefetches: bool,
        requests: Mutex<Vec<String>>,
    }

    fn key(repo_url: &str, path: &str) -> (String, String) {
        (
            repo_url.trim_end_matches('/').to_string(),
            path.trim_start_matches('/').to_string(),
        )
    }

    impl MemoryPomSource {
        pub(crate) fn new(security: SecurityConfig) -> Self {
            Self {
                security,
                ..Self::default()
            }
        }

        /// Serve each path of `files` from `repo_url`.
        pub(crate) fn with_files<'a>(
            mut self,
            repo_url: &str,
            files: impl IntoIterator<Item = (&'a String, &'a Vec<u8>)>,
        ) -> Self {
            for (path, bytes) in files {
                self.files
                    .insert(key(repo_url, path), Bytes::from(bytes.clone()));
            }
            self
        }

        /// Refuse every request to this repository with the given HTTP status.
        pub(crate) fn with_refusal(mut self, repo_url: &str, code: u16) -> Self {
            self.refusals.insert(
                repo_url.trim_end_matches('/').to_string(),
                reqwest::StatusCode::from_u16(code).unwrap(),
            );
            self
        }

        /// Count every request to this repository as sent with a credential.
        pub(crate) fn with_credential(mut self, repo_url: &str) -> Self {
            self.credentialed.push(key(repo_url, "").0);
            self
        }

        /// Serve prefetches too.
        pub(crate) fn prefetching(mut self) -> Self {
            self.prefetches = true;
            self
        }

        /// Answer every request for `path` only after `delay`.
        pub(crate) fn with_delay(mut self, path: &str, delay: std::time::Duration) -> Self {
            self.delays
                .insert(path.trim_start_matches('/').to_string(), delay);
            self
        }

        /// Every path requested so far, after its repository URL.
        pub(crate) fn requests(&self) -> Vec<String> {
            self.requests.lock().unwrap().clone()
        }

        fn get(&self, repo: &Repository, path: &str) -> Result<Bytes, RepoError> {
            let key = key(&repo.url, path);
            self.requests
                .lock()
                .unwrap()
                .push(format!("{}/{}", key.0, key.1));
            if let Some(&status) = self.refusals.get(&key.0) {
                let url = format!("{}/{}", key.0, key.1);
                return Err(match status.as_u16() {
                    401 | 403 | 407 => RepoError::Unauthorized {
                        status,
                        url,
                        redirected_to: None,
                        sent: None,
                    },
                    _ => RepoError::HttpStatus {
                        status,
                        url,
                        redirected_to: None,
                        retry_after: None,
                    },
                });
            }
            self.files
                .get(&key)
                .cloned()
                .ok_or_else(|| RepoError::NotFound(key.1.into()))
        }
    }

    impl PomSource for MemoryPomSource {
        fn sends_credential(&self, repo: &Repository) -> bool {
            self.credentialed.contains(&key(&repo.url, "").0)
        }

        fn admit(&self, repos: Vec<Repository>, from: Declaration) -> Admission {
            RepositoryPolicy::screen(
                &rv_config::Config::for_testing_with(
                    ".".into(),
                    rv_config::ResolvedPaths::for_testing().unwrap(),
                    Vec::new(),
                    self.security.clone(),
                ),
                repos,
                from,
            )
        }

        fn effective_repository(&self, repo: &Repository) -> Repository {
            repo.clone()
        }

        fn pom<'a>(
            &'a self,
            repo: &'a Repository,
            request: &'a ArtifactRequest,
        ) -> BoxFuture<'a, Result<(Bytes, String), RepoError>> {
            let path = request.pom().to_path();
            let delay = self.delays.get(path.trim_start_matches('/')).copied();
            let found = self.get(repo, &path).map(|bytes| (bytes, path));
            Box::pin(async move {
                if let Some(delay) = delay {
                    tokio::time::sleep(delay).await;
                }
                found
            })
        }

        fn prefetch_pom<'a>(
            &'a self,
            repo: &'a Repository,
            request: &'a ArtifactRequest,
        ) -> BoxFuture<'a, Result<Option<Bytes>, RepoError>> {
            let read = self.prefetches.then(|| self.pom(repo, request));
            Box::pin(async move {
                match read {
                    Some(read) => read.await.map(|(bytes, _)| Some(bytes)),
                    None => Ok(None),
                }
            })
        }

        fn metadata<'a>(
            &'a self,
            repo: &'a Repository,
            coord: &'a Coord,
        ) -> BoxFuture<'a, Result<Metadata, RepoError>> {
            let path = format!(
                "{}/{}/maven-metadata.xml",
                coord.group_id.as_str().replace('.', "/"),
                coord.artifact_id
            );
            let found = self.get(repo, &path);
            Box::pin(async move {
                let bytes = found?;
                Metadata::parse(&String::from_utf8_lossy(&bytes))
            })
        }

        fn snapshot<'a>(
            &'a self,
            _repo: &'a Repository,
            coord: &'a Coord,
        ) -> BoxFuture<'a, Result<SnapshotResolution, RepoError>> {
            let coord = coord.to_string();
            Box::pin(async move { Err(RepoError::NotFound(coord.into())) })
        }
    }
}
