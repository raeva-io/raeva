//! Which repositories a resolution uses, and what each may do. What a
//! repository may do follows where it was declared ([`Provenance`]), never a
//! separate grant.

use std::collections::HashSet;
use std::sync::{Arc, LazyLock, Mutex};

use rv_config::Config;

use crate::auth::NamedOrigins;
use crate::repository::Repository;
use crate::transport::Grants;

/// Where a repository was declared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Provenance {
    /// Built by the caller with [`Repository::new`] or read back from disk.
    /// The caller vouches for it, as for a configured repository.
    #[default]
    Caller,
    /// `raeva.toml`, the user `config.toml` or `settings.xml`.
    Configured,
    /// The `<repositories>` of the project's own POM or of a parent POM read
    /// from the project directory.
    LocalPom,
    /// The `<repositories>` of a POM fetched from a repository: a remote
    /// parent of the project, a dependency or an imported BOM.
    FetchedPom,
}

/// Which POM declared the repositories passed to [`RepositoryPolicy::admit`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Declaration {
    /// The project's own POM or a parent read from the project directory.
    LocalPom,
    /// A parent of the project fetched from a repository. Maven uses its
    /// repositories, so they are admitted, but as a fetched POM's, and only
    /// over HTTP or HTTPS.
    RemoteParent,
    /// A dependency or imported BOM, admitted only when the
    /// `[security]` transitive repository policy allows it.
    Transitive,
}

/// The repositories [`RepositoryPolicy::admit`] accepted and refused, in
/// the order given.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct Admission {
    /// The repositories to use, with their provenance set.
    pub admitted: Vec<Repository>,
    /// The repositories refused: a remote parent's non-HTTP(S) URL, or a
    /// transitive URL the `[security]` policy does not allow.
    pub dropped: Vec<Repository>,
    /// The repositories refused whatever the policy allows, because their
    /// URL may hold a secret ([`secret_url_refusal`]), which raeva.lock
    /// would record.
    pub secret_urls: Vec<Repository>,
    /// External HTTP repositories refused by the built-in blocker.
    pub blocked_http: Vec<Repository>,
}

/// The one place that decides what a declared repository may do.
///
/// | Provenance | Used | Private address | Redirect authority |
/// |---|---|---|---|
/// | `Caller`, `Configured`, `LocalPom` | yes | yes | yes |
/// | `FetchedPom` from a remote parent | over HTTP(S) | if the transitive policy allows its URL | no |
/// | `FetchedPom` from a dependency or BOM | if the transitive policy allows its URL | yes, when used | no |
///
/// POM repositories using external HTTP are refused unless configuration
/// declares the same URL or a matching mirror, as with Maven's HTTP blocker.
///
/// "Private address" is a direct connection to a host that resolves, or an
/// IP literal that points, outside the public internet. "Redirect
/// authority" lets the repository's origin send raeva on one cross-origin
/// redirect, as a configured repository may.
#[derive(Clone)]
pub struct RepositoryPolicy {
    config: Arc<Config>,
    grants: Grants,
    /// Where a local declaration's origin is recorded, so that an id-scoped
    /// credential may follow a fetched POM's repository there.
    named_origins: Option<NamedOrigins>,
    /// [`Config::secret_named_inputs`], which a URL path may not hold.
    secrets: Arc<[(String, String)]>,
}

impl RepositoryPolicy {
    pub(crate) fn new(
        config: &Config,
        grants: Grants,
        named_origins: Option<NamedOrigins>,
    ) -> Self {
        Self {
            config: Arc::new(config.clone()),
            grants,
            named_origins,
            secrets: config.secret_named_inputs().into(),
        }
    }

    /// Accept the repositories one POM declares, record `from` as their
    /// provenance, and give each what its provenance allows.
    pub fn admit(
        &self,
        repos: impl IntoIterator<Item = Repository>,
        from: Declaration,
    ) -> Admission {
        let admission = Self::screen_with(&self.config, &self.secrets, repos, from);
        for repo in &admission.admitted {
            self.grant(repo);
        }
        admission
    }

    /// Which of `repos` [`Self::admit`] accepts, with their provenance
    /// recorded, for a caller that has no client to grant anything through.
    pub fn screen(
        config: &Config,
        repos: impl IntoIterator<Item = Repository>,
        from: Declaration,
    ) -> Admission {
        Self::screen_with(config, &config.secret_named_inputs(), repos, from)
    }

    fn screen_with(
        config: &Config,
        secrets: &[(String, String)],
        repos: impl IntoIterator<Item = Repository>,
        from: Declaration,
    ) -> Admission {
        let mut admission = Admission::default();
        for mut repo in repos {
            let provenance = match from {
                Declaration::LocalPom => Provenance::LocalPom,
                Declaration::RemoteParent | Declaration::Transitive => Provenance::FetchedPom,
            };
            repo.set_provenance(provenance);
            if secret_url_refusal(&repo.url, secrets).is_some() {
                admission.secret_urls.push(repo);
                continue;
            }
            if http_repository_blocked(config, &repo, from != Declaration::Transitive) {
                admission.blocked_http.push(repo);
                continue;
            }
            let admitted = match from {
                Declaration::LocalPom => true,
                // A fetched POM never points raeva at the local file system.
                Declaration::RemoteParent => url::Url::parse(&repo.url)
                    .is_ok_and(|url| matches!(url.scheme(), "http" | "https")),
                Declaration::Transitive => config.security.allows_transitive_repo_url(&repo.url),
            };
            if admitted {
                admission.admitted.push(repo);
            } else {
                admission.dropped.push(repo);
            }
        }
        admission
    }

    /// Give `repo` what its provenance allows.
    fn grant(&self, repo: &Repository) {
        let fetched = repo.provenance() == Provenance::FetchedPom;
        if !fetched || self.config.security.allows_transitive_repo_url(&repo.url) {
            self.grants.exempt(repo);
        }
        if !fetched {
            self.grants.authorize_issuer(repo);
            if let Some(named) = &self.named_origins {
                named.add(&repo.url);
            }
        }
    }
}

/// Why `url` may not be used, as a clause after "its URL", or `None` when
/// it may: it has a part [`rv_config::secret_url_part`] names, or the value
/// of one of `secrets` ([`Config::secret_named_inputs`]) makes up whole
/// segments of its path. The clause names the input, never its value, and
/// says what to do instead.
pub fn secret_url_refusal(url: &str, secrets: &[(String, String)]) -> Option<String> {
    if let Some(part) = rv_config::secret_url_part(url) {
        return Some(format!(
            "has {part}, which raeva.lock would record; put credentials in an [[auth]] entry \
             in config.toml or a <server> in settings.xml with the repository's id, not in the \
             URL"
        ));
    }
    rv_config::secret_input_in_path(url, secrets).map(|input| {
        format!(
            "has the value of {input} as one or more whole path segments, which raeva.lock \
             would record, and that name looks like a secret's; if the value is a token, give \
             the URL with it to a settings.xml <mirror> of the repository, whose URL \
             raeva.lock does not record, or put the credential in a <server> with the \
             repository's id; if it is not a secret, rename {input}"
        )
    })
}

static HTTP_REPO_WARNED: LazyLock<Mutex<HashSet<(String, bool)>>> = LazyLock::new(Mutex::default);

/// Refuse external HTTP declared by a POM unless the user configured the URL
/// or a matching mirror, as with Maven's default HTTP blocker. `project`
/// tells whether the project or its parents declared it, which raeva reports
/// without `-v`.
pub(crate) fn http_repository_blocked(config: &Config, repo: &Repository, project: bool) -> bool {
    if !url::Url::parse(&repo.url).is_ok_and(|url| url.scheme() == "http")
        || !crate::mirror::is_external_repo(&repo.url)
        || config.repositories().iter().any(|configured| {
            crate::repository::normalize_repo_url(&configured.url)
                == crate::repository::normalize_repo_url(&repo.url)
        })
        || crate::mirror::resolve_mirror(config.mirrors(), repo)
            .1
            .is_some()
    {
        return false;
    }
    let key = (crate::repository::normalize_repo_url(&repo.url), project);
    let url = rv_config::redact_url(&repo.url);
    rv_maven_model::held::when_shown(move || {
        if HTTP_REPO_WARNED
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key)
        {
            tracing::warn!(
                sec_code = "HTTP_REPO_BLOCKED",
                url = %url,
                project,
                "ignoring repository {url} that a POM declares: plain HTTP to a host that is \
                 not loopback, which Maven's default HTTP blocker refuses; mirror it or declare \
                 the URL in raeva.toml, config.toml or settings.xml"
            );
        }
    });
    true
}

impl std::fmt::Debug for RepositoryPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RepositoryPolicy")
            .field("security", &self.config.security)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use rv_config::{Config, ResolvedPaths, SecurityConfig};

    use super::{Declaration, Provenance, RepositoryPolicy};
    use crate::error::RepoError;
    use crate::repository::Repository;
    use crate::transport::ClientSet;

    fn config(security: SecurityConfig) -> Config {
        Config::for_testing_with(
            ".".into(),
            ResolvedPaths::for_testing().unwrap(),
            Vec::new(),
            security,
        )
    }

    fn policy(allowlist: &[&str]) -> (RepositoryPolicy, ClientSet) {
        let transport = ClientSet::screened();
        let mut security = SecurityConfig::default();
        security.transitive_repository_allowlist =
            allowlist.iter().map(|s| s.to_string()).collect();
        (
            RepositoryPolicy::new(&config(security), transport.grants(), None),
            transport,
        )
    }

    fn repo(url: &str) -> Repository {
        Repository::new(None, url, true, false)
    }

    fn repos(urls: &[&str]) -> Vec<Repository> {
        urls.iter().map(|url| repo(url)).collect()
    }

    fn trusts(transport: &ClientSet, origin: &str) -> bool {
        transport.trusts_origin(&url::Url::parse(origin).unwrap())
    }

    /// Maven uses a remote parent's repositories, so raeva does too, but a
    /// fetched POM chooses neither a private address nor a redirect, and
    /// never the local file system.
    #[test]
    fn capabilities_follow_the_declaration() {
        use Declaration::*;
        // (allowlist, from, declared, dropped, trusted, untrusted); only a
        // local POM authorizes a redirect issuer.
        type Urls = &'static [&'static str];
        #[rustfmt::skip]
        let cases: &[(Urls, Declaration, Urls, Urls, Urls, Urls)] = &[
            (&[], LocalPom, &["https://nexus.corp/maven/"], &[], &["https://nexus.corp/"], &[]),
            (&[], LocalPom, &["file:///srv/maven/"], &[], &[], &[]),
            (&[], RemoteParent, &["https://internal.corp/maven/"], &[], &[], &["https://internal.corp/"]),
            (&["https://internal.corp/maven/"], RemoteParent, &["https://internal.corp/maven/"], &[], &["https://internal.corp/"], &[]),
            (&["https://approved.corp/"], Transitive, &["https://approved.corp/maven/", "https://other.corp/maven/"],
                &["https://other.corp/maven/"], &["https://approved.corp/"], &["https://other.corp/"]),
            (&[], RemoteParent, &["file:///home/user/.m2/repository/", "https://repo.example/maven/"],
                &["file:///home/user/.m2/repository/"], &[], &[]),
        ];
        for (allowlist, from, declared, dropped, trusted, untrusted) in cases {
            let (policy, transport) = policy(allowlist);
            let admission = policy.admit(repos(declared), *from);
            let admitted: Vec<&str> = declared
                .iter()
                .copied()
                .filter(|url| !dropped.contains(url))
                .collect();
            assert_eq!(
                admission.admitted,
                repos(&admitted),
                "{from:?} {declared:?}"
            );
            assert_eq!(admission.dropped, repos(dropped), "{from:?} {declared:?}");
            let provenance = if *from == LocalPom {
                Provenance::LocalPom
            } else {
                Provenance::FetchedPom
            };
            assert!(
                admission
                    .admitted
                    .iter()
                    .all(|r| r.provenance() == provenance)
            );
            for origin in *trusted {
                assert!(trusts(&transport, origin), "{origin}");
                assert_eq!(transport.authorizes_issuer(origin), *from == LocalPom);
            }
            for origin in *untrusted {
                assert!(!trusts(&transport, origin), "{origin}");
                assert!(!transport.authorizes_issuer(origin), "{origin}");
            }
        }

        let mut open = SecurityConfig::default();
        open.allow_transitive_repositories = true;
        let screened = RepositoryPolicy::screen(
            &config(open),
            [repo("file:///srv/maven/")],
            Declaration::Transitive,
        );
        assert!(screened.admitted.is_empty());
    }

    #[test]
    fn a_url_with_a_secret_part_is_refused_from_every_pom() {
        let (policy, transport) = policy(&["https://"]);
        for from in [
            Declaration::LocalPom,
            Declaration::RemoteParent,
            Declaration::Transitive,
        ] {
            let admission = policy.admit(
                [
                    repo("https://user:pass@nexus.corp/maven/"),
                    repo("https://nexus.corp/maven/?token=x"),
                ],
                from,
            );
            assert!(admission.admitted.is_empty(), "{from:?}");
            assert!(admission.dropped.is_empty(), "{from:?}");
            assert_eq!(admission.secret_urls.len(), 2, "{from:?}");
        }
        assert!(!transport.authorizes_issuer("https://nexus.corp/"));
    }

    #[test]
    fn a_private_ip_literal_needs_a_local_declaration() {
        let (policy, transport) = policy(&[]);
        let public = url::Url::parse("https://93.184.215.14/maven/a.pom").unwrap();
        assert!(transport.client_for(&public).is_ok());
        for base in [
            "https://10.0.0.5:8081/maven/",
            "https://[fd00::1]/maven/",
            "https://[::ffff:10.0.0.9]/maven/",
        ] {
            let pom = url::Url::parse(base).unwrap().join("a.pom").unwrap();
            policy.admit([repo(base)], Declaration::RemoteParent);
            let err = transport.client_for(&pom).unwrap_err();
            assert!(matches!(err, RepoError::NonGlobalAddress { .. }), "{err}");
            policy.admit([repo(base)], Declaration::LocalPom);
            assert!(transport.client_for(&pom).is_ok(), "{base}");
        }
        // The exemption covers the declared origin only: another port or
        // scheme on the same address is another service on that machine.
        policy.admit([repo("https://nexus.corp/maven/")], Declaration::LocalPom);
        assert!(trusts(&transport, "https://nexus.corp:443/"));
        for other in [
            "http://10.0.0.5:6379/maven/a.pom",
            "http://10.0.0.5/maven/a.pom",
            "https://10.0.0.5:8443/maven/a.pom",
        ] {
            let other = url::Url::parse(other).unwrap();
            assert!(!transport.trusts_origin(&other), "{other}");
            assert!(
                matches!(
                    transport.client_for(&other),
                    Err(RepoError::NonGlobalAddress { .. })
                ),
                "{other}"
            );
        }
        assert!(!trusts(&transport, "https://nexus.corp:8443/"));
        assert!(!trusts(&transport, "http://nexus.corp/"));
    }

    #[test]
    fn external_http_requires_user_configuration() {
        let mut config = config(SecurityConfig::default());
        config.security.allow_transitive_repositories = true;
        let transport = ClientSet::screened();
        let policy = RepositoryPolicy::new(&config, transport.grants(), None);
        let output = rv_test_support::capture_warnings(|| {
            for from in [
                Declaration::LocalPom,
                Declaration::RemoteParent,
                Declaration::Transitive,
            ] {
                let admission = policy.admit([repo("http://repo.example/")], from);
                assert!(admission.admitted.is_empty(), "{from:?}");
                assert!(admission.dropped.is_empty(), "{from:?}");
                assert_eq!(admission.blocked_http, [repo("http://repo.example/")]);
                // Maven's blocker spares `localhost` and `127.0.0.1` only.
                let loopback = repo("http://[::1]:8080/");
                let admission = policy.admit([loopback.clone()], from);
                assert_eq!(admission.blocked_http, [loopback]);
                for url in [
                    "http://127.0.0.1:8080/",
                    "http://localhost:8080/",
                    "https://repo.example/",
                ] {
                    assert_eq!(policy.admit([repo(url)], from).admitted, [repo(url)]);
                }
            }
        });
        // Once for the project and its parents, and once for dependencies,
        // which raeva shows only at -v.
        assert_eq!(output.matches("HTTP_REPO_BLOCKED").count(), 4, "{output}");
        assert_eq!(output.matches("project=true").count(), 2, "{output}");
        assert!(output.contains("http://repo.example/"), "{output}");
        assert!(!trusts(&transport, "http://repo.example/"));

        let configured = Config::for_testing_with_repos(
            ".".into(),
            ResolvedPaths::for_testing().unwrap(),
            vec![rv_config::RepoConfig::new(
                Some("user"),
                "http://repo.example",
            )],
        );
        let mut mirror = rv_config::MirrorConfig::new(Some("safe"), "https://mirror.example/");
        mirror.mirror_of = vec!["external:http:*".into()];
        let mirrored = config.clone().with_mirrors(vec![mirror]);
        let mut excluded = rv_config::MirrorConfig::new(Some("safe"), "https://mirror.example/");
        excluded.mirror_of = vec!["external:http:*,!legacy".into()];
        let excluded = config.with_mirrors(vec![excluded]);
        let legacy = Repository::new(Some("legacy".into()), "http://repo.example/", true, false);
        for config in [configured, mirrored] {
            assert_eq!(
                RepositoryPolicy::screen(&config, [legacy.clone()], Declaration::LocalPom).admitted,
                std::slice::from_ref(&legacy)
            );
        }
        assert!(
            RepositoryPolicy::screen(&excluded, [legacy], Declaration::LocalPom)
                .admitted
                .is_empty()
        );
    }

    #[test]
    fn provenance_is_not_part_of_equality() {
        let mut pom = rv_maven_model::Repository::new(None, "https://repo.example/");
        pom.snapshots_enabled = false;
        assert_eq!(Repository::from(pom), repo("https://repo.example/"));
    }
}
