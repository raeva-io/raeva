//! POM fetcher and parent resolver that wrap the resolver's RepoBackend.

use std::path::PathBuf;

use rv_maven_model::{Parent, Pom, PomError};
use rv_version::Coord;

use crate::context::ResolveContext;
use crate::error::ResolveError;
use crate::parent_resolver::{ParentResolverBase, RemotePomFetcher};

use super::RepoBackend;

#[derive(Clone)]
pub(super) struct RepoBackendFetcher {
    backend: RepoBackend,
}

impl RepoBackendFetcher {
    fn new(backend: RepoBackend) -> Self {
        Self { backend }
    }
}

impl RemotePomFetcher for RepoBackendFetcher {
    fn context(&self) -> Option<&ResolveContext> {
        Some(&self.backend.ctx)
    }

    fn fetch_local_pom_by_coord(
        &self,
        coord: &Coord,
    ) -> std::result::Result<Option<Pom>, PomError> {
        Ok(self.backend.workspace_pom_for_coord(coord))
    }

    fn fetch_pom_by_coord(&self, coord: &Coord) -> std::result::Result<Option<Pom>, PomError> {
        match self.backend.fetch_pom_bytes_blocking(coord) {
            Ok((bytes, blob)) => {
                let xml = std::str::from_utf8(&bytes)
                    .map_err(|err| PomError::InvalidModel(err.to_string()))?;
                let pom = self
                    .backend
                    .ctx
                    .parsed_poms()
                    .parse(&blob, xml)
                    .map_err(|err| PomError::InvalidModel(format!("{coord}: {err}")))?;
                Ok(Some(pom))
            }
            Err(ResolveError::ArtifactNotFound { .. }) => Ok(None),
            Err(err) => Err(PomError::InvalidModel(err.to_string())),
        }
    }
}

/// Whether the POM's `<repositories>` bypass the security gate. Root POMs
/// are user-authored and always trusted; transitive POMs go through
/// `RepoBackend::extend_repos` (which honours `allow_transitive_repositories`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RepoTrust {
    Root,
    Transitive,
}

pub(super) struct RepoParentResolver {
    base: ParentResolverBase<RepoBackendFetcher>,
    trust: RepoTrust,
}

impl RepoParentResolver {
    /// Full constructor.
    ///
    /// `project_root` is the workspace/project root used for the
    /// `<relativePath>` containment check. Paths resolved from
    /// `<relativePath>` that escape `project_root` are silently rejected
    /// and fall through to remote resolution. When `project_root` is
    /// `None` the containment check is skipped (legacy permissive behaviour).
    ///
    /// For production callers: pass the top-level project directory (which
    /// may be a parent of `base_dir` for multi-module builds), so legitimate
    /// `../pom.xml` traversal is permitted while deeper escapes are blocked.
    pub(super) fn with_strict_and_trust(
        backend: RepoBackend,
        base_dir: Option<PathBuf>,
        project_root: Option<PathBuf>,
        strict: bool,
        trust: RepoTrust,
    ) -> Self {
        let fetcher = RepoBackendFetcher::new(backend);
        let mut base = ParentResolverBase::new(base_dir, fetcher, strict);
        base.project_root = project_root;
        Self { base, trust }
    }

    /// Defaults to [`RepoTrust::Transitive`] for callers that haven't yet
    /// audited root-vs-transitive intent.
    pub(super) fn with_strict(
        backend: RepoBackend,
        base_dir: Option<PathBuf>,
        strict: bool,
    ) -> Self {
        // Transitive-POM resolvers always have base_dir=None (remote fetch),
        // so project_root is irrelevant here.
        Self::with_strict_and_trust(backend, base_dir, None, strict, RepoTrust::Transitive)
    }

    #[cfg(test)]
    pub(super) fn load_local_parent(&self, parent: &Parent) -> Option<Pom> {
        self.base.load_local_parent(parent)
    }
}

impl rv_maven_model::ParentResolver for RepoParentResolver {
    fn is_root_model(&self) -> bool {
        self.trust == RepoTrust::Root
    }

    fn resolve_parent(&self, parent: &Parent) -> std::result::Result<Option<Pom>, PomError> {
        if self.trust == RepoTrust::Root
            && let Some(mut pom) = self.base.load_local_parent(parent)
        {
            pom.mark_root_repositories();
            return Ok(Some(pom));
        }
        self.base.resolve_parent(parent)
    }

    fn resolve_import_pom(
        &self,
        group_id: &str,
        artifact_id: &str,
        version: &str,
        type_: Option<&str>,
        classifier: Option<&str>,
    ) -> std::result::Result<Option<Pom>, PomError> {
        self.base
            .resolve_import_pom(group_id, artifact_id, version, type_, classifier)
    }

    fn strict_parent_resolution(&self) -> bool {
        self.base.strict
    }

    fn strict_bom_resolution(&self) -> bool {
        self.base.strict
    }

    fn observe_project_repositories(&self, repositories: &[rv_maven_model::Repository]) {
        // Merge declared `<repositories>` before the parent fetch runs. A
        // POM that hosts its own parent on a custom repo needs the repo
        // visible during inheritance, and post-resolution merging is too late.
        if let Some(client) = self.base.fetcher.backend.ctx.client.as_ref() {
            let root_repos: Vec<_> = repositories
                .iter()
                .filter(|repo| repo.root_declared)
                .cloned()
                .map(rv_repo::Repository::from)
                .collect();
            client.trust_root_repositories(&root_repos);
        }
        let repos = repositories.iter().cloned().map(rv_repo::Repository::from);
        match self.trust {
            RepoTrust::Root => self.base.fetcher.backend.extend_repos_trusted(repos),
            RepoTrust::Transitive => self.base.fetcher.backend.extend_repos(repos, None),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{RepoParentResolver, RepoTrust};
    use crate::context::ResolveContext;
    use crate::resolver::RepoBackend;
    use rv_config::{Config, Platform, ResolvedPaths};
    use rv_maven_model::ParentResolver as _;
    use rv_store::Store;

    fn backend_with_default_policy() -> RepoBackend {
        let project_tmp = tempfile::tempdir().unwrap();
        let paths = ResolvedPaths::for_testing().expect("paths");
        let config =
            Config::for_testing_with_repos(project_tmp.path().to_path_buf(), paths, Vec::new());
        let store_tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(store_tmp.path()).expect("store"));
        let platform = Platform::new("linux", "x86_64").unwrap();
        let ctx = ResolveContext::new(config, Vec::new(), store, platform, None);
        RepoBackend::new(&ctx, Vec::new(), false)
    }

    fn declared_repo(id: &str, url: &str) -> rv_maven_model::Repository {
        rv_maven_model::Repository {
            root_declared: false,
            id: Some(id.into()),
            url: url.into(),
            releases_enabled: true,
            snapshots_enabled: false,
            releases_update_policy: None,
            snapshots_update_policy: None,
            releases_checksum_policy: None,
            snapshots_checksum_policy: None,
        }
    }

    /// Test redirect authority through model observation and HTTP client selection.
    /// HTTP distinguishes authorized issuers rejected for transport from untrusted issuers,
    /// without TLS fixtures or external network access.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn root_model_redirect_grants_follow_provenance() {
        use rv_maven_model::{ActivationContext, Pom};
        use rv_repo::{RedirectRejectionKind, RepoClient, RepoError, Repository};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let _ = rustls::crypto::ring::default_provider().install_default();
        for (trust, local_parent) in [
            (RepoTrust::Root, false),
            (RepoTrust::Root, true),
            (RepoTrust::Transitive, false),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let repo_url = format!("http://{}/repo/", listener.local_addr().unwrap());
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut buffer = [0; 8192];
                assert!(socket.read(&mut buffer).await.unwrap() > 0);
                socket.write_all(b"HTTP/1.1 302 Found\r\nLocation: https://storage.example/artifact\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
            });
            let paths = ResolvedPaths::from_raeva_home(tmp.path().join("raeva"));
            let mut config =
                Config::for_testing_with_repos(tmp.path().to_owned(), paths, Vec::new());
            config.security.allow_transitive_repositories = true;
            let client = RepoClient::new(&config).await.unwrap();
            let store = Arc::new(Store::open(&tmp.path().join("store")).unwrap());
            let ctx = ResolveContext::new(
                config,
                Vec::new(),
                store,
                Platform::new("linux", "x86_64").unwrap(),
                Some(client.clone()),
            );
            // Starting URLs, including lockfile-derived URLs, must not grant
            // redirect authority. Only model observation may grant it.
            let repo = Repository::new(None, &repo_url, true, false);
            let backend = RepoBackend::new(&ctx, vec![repo.clone()], false);
            let declarations = format!(
                r#"
                <properties><registry>{repo_url}</registry></properties>
                <profiles><profile><id>active</id><activation><activeByDefault>true</activeByDefault></activation>
                <repositories><repository><id>root</id><url>${{registry}}</url><root_declared>true</root_declared></repository></repositories>
                </profile></profiles>"#
            );
            let base = tmp.path().join("child");
            std::fs::create_dir(&base).unwrap();
            let xml = if local_parent {
                std::fs::write(tmp.path().join("pom.xml"), format!("<project><groupId>g</groupId><artifactId>parent</artifactId><version>1</version>{declarations}</project>")).unwrap();
                "<project><parent><groupId>g</groupId><artifactId>parent</artifactId><version>1</version></parent><artifactId>child</artifactId></project>".to_string()
            } else {
                format!(
                    "<project><groupId>g</groupId><artifactId>child</artifactId><version>1</version>{declarations}</project>"
                )
            };
            let resolver = RepoParentResolver::with_strict_and_trust(
                backend,
                Some(base),
                Some(tmp.path().to_owned()),
                true,
                trust,
            );
            super::super::backend::build_project_off_task(
                Pom::parse(&xml).unwrap(),
                resolver,
                ActivationContext::default(),
            )
            .await
            .unwrap();
            let error = client
                .fetch_metadata(&repo, &"g:artifact:1".parse().unwrap())
                .await
                .unwrap_err();
            let expected = if trust == RepoTrust::Root {
                RedirectRejectionKind::InsecureOrigin
            } else {
                RedirectRejectionKind::OriginNotConfigured
            };
            assert!(
                matches!(error, RepoError::RedirectRejected { kind, .. } if kind == expected),
                "{trust:?}, local_parent={local_parent}: {error}"
            );
            server.await.unwrap();
        }
    }

    #[test]
    fn observe_with_trust_root_bypasses_policy() {
        let backend = backend_with_default_policy();
        let backend_clone = backend.clone();
        let resolver =
            RepoParentResolver::with_strict_and_trust(backend, None, None, false, RepoTrust::Root);

        resolver.observe_project_repositories(&[declared_repo(
            "custom",
            "https://custom.example/repo/",
        )]);

        assert!(
            backend_clone
                .repos_snapshot()
                .iter()
                .any(|r| r.url == "https://custom.example/repo/"),
            "root-trust observe must merge despite default-deny policy"
        );
    }

    #[test]
    fn observe_with_trust_transitive_is_gated_by_default() {
        let backend = backend_with_default_policy();
        let backend_clone = backend.clone();
        let resolver = RepoParentResolver::with_strict_and_trust(
            backend,
            None,
            None,
            false,
            RepoTrust::Transitive,
        );

        resolver.observe_project_repositories(&[declared_repo(
            "attacker",
            "https://attacker.example/repo/",
        )]);

        assert!(
            !backend_clone
                .repos_snapshot()
                .iter()
                .any(|r| r.url == "https://attacker.example/repo/"),
            "transitive observe must be filtered under default-deny policy"
        );
    }

    #[test]
    fn with_strict_defaults_to_transitive_trust() {
        let backend = backend_with_default_policy();
        let backend_clone = backend.clone();
        let resolver = RepoParentResolver::with_strict(backend, None, false);

        resolver.observe_project_repositories(&[declared_repo(
            "attacker",
            "https://attacker.example/repo/",
        )]);

        assert!(
            !backend_clone
                .repos_snapshot()
                .iter()
                .any(|r| r.url == "https://attacker.example/repo/"),
            "with_strict back-compat must default to gated transitive trust"
        );
    }

    #[test]
    fn observe_with_trust_transitive_merges_when_policy_opens() {
        let project_tmp = tempfile::tempdir().unwrap();
        let paths = ResolvedPaths::for_testing().expect("paths");
        let mut config =
            Config::for_testing_with_repos(project_tmp.path().to_path_buf(), paths, Vec::new());
        config.security.allow_transitive_repositories = true;

        let store_tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(store_tmp.path()).expect("store"));
        let platform = Platform::new("linux", "x86_64").unwrap();
        let ctx = ResolveContext::new(config, Vec::new(), store, platform, None);
        let backend = RepoBackend::new(&ctx, Vec::new(), false);
        let backend_clone = backend.clone();
        let resolver = RepoParentResolver::with_strict_and_trust(
            backend,
            None,
            None,
            false,
            RepoTrust::Transitive,
        );

        resolver.observe_project_repositories(&[declared_repo(
            "vendor",
            "https://vendor.example/repo/",
        )]);

        assert!(
            backend_clone
                .repos_snapshot()
                .iter()
                .any(|r| r.url == "https://vendor.example/repo/"),
            "transitive observe must merge when policy is open"
        );
    }
}
