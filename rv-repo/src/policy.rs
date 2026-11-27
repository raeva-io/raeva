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
    /// `[security]` transitive repository policy allows it. Maven 3.10
    /// collects that POM's dependencies through it as a descriptor
    /// repository, which gets no settings.xml password.
    Transitive,
    /// [`Self::Transitive`] for the parent and imported BOMs of that POM's
    /// own model, which Maven's model resolver fetches with the session's
    /// credentials.
    TransitiveModel,
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
    /// URL or id may hold a secret ([`secret_url_refusal`],
    /// [`secret_id_refusal`]).
    pub secret_urls: Vec<Repository>,
    /// External HTTP repositories refused by the built-in blocker.
    pub blocked_http: Vec<Repository>,
}

/// The one place that decides what a declared repository may do.
///
/// | Provenance | Used | Private address | Redirect authority |
/// |---|---|---|---|
/// | `Caller`, `Configured`, `LocalPom` | yes | yes | yes |
/// | `FetchedPom` from a remote parent | over HTTP(S), or through a mirror that matches it | if the transitive policy allows its URL | no |
/// | `FetchedPom` from a dependency or BOM | if the transitive policy allows its URL | yes, when used | no |
///
/// POM repositories using external HTTP are refused unless configuration
/// declares the same URL or a matching mirror, as with Maven's HTTP blocker.
///
/// "Private address" is a direct connection to a host that resolves, or an
/// IP literal that points, outside the public internet. "Redirect
/// authority" lets the repository's origin start a chain of cross-origin
/// redirects, as a configured repository may.
#[derive(Clone)]
pub struct RepositoryPolicy {
    config: Arc<Config>,
    grants: Grants,
    /// Where a local declaration's origin is recorded, so that an id-scoped
    /// credential may follow a fetched POM's repository there.
    named_origins: Option<NamedOrigins>,
    /// [`Config::secret_named_inputs`], which a URL path may not hold.
    secrets: Arc<[(String, String)]>,
    /// [`Config::secret_input_names`].
    secret_names: Arc<[(String, String)]>,
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
            secret_names: config.secret_input_names().into(),
        }
    }

    /// Accept the repositories one POM declares, record `from` as their
    /// provenance, and give each what its provenance allows.
    pub fn admit(
        &self,
        repos: impl IntoIterator<Item = Repository>,
        from: Declaration,
    ) -> Admission {
        let admission =
            Self::screen_with(&self.config, &self.secrets, &self.secret_names, repos, from);
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
        let (secrets, names) = config.secret_inputs();
        Self::screen_with(config, &secrets, &names, repos, from)
    }

    /// [`Self::screen`] with the configuration's
    /// [`Config::secret_inputs`] already read, for a caller that screens
    /// many declarations.
    pub fn screen_with(
        config: &Config,
        secrets: &[(String, String)],
        names: &[(String, String)],
        repos: impl IntoIterator<Item = Repository>,
        from: Declaration,
    ) -> Admission {
        let mut admission = Admission::default();
        for mut repo in repos {
            let provenance = match from {
                Declaration::LocalPom => Provenance::LocalPom,
                Declaration::RemoteParent
                | Declaration::Transitive
                | Declaration::TransitiveModel => Provenance::FetchedPom,
            };
            let transitive = matches!(from, Declaration::Transitive | Declaration::TransitiveModel);
            repo.set_provenance(provenance);
            repo.set_descriptor(from == Declaration::Transitive);
            if secret_part_refusal(&repo.url, repo.url_reads(), secrets, names).is_some()
                || secret_id_refusal(repo.id.as_deref(), repo.id_reads(), secrets, names).is_some()
            {
                admission.secret_urls.push(repo);
                continue;
            }
            if http_repository_blocked(config, &repo, !transitive) {
                admission.blocked_http.push(repo);
                continue;
            }
            // The transitive policy drops a dependency's repository before
            // anything else about it counts.
            if transitive && !config.security.allows_transitive_repo_url(&repo.url) {
                admission.dropped.push(repo);
                continue;
            }
            // Maven 3.9 keeps such a repository and fails the build once it
            // searches it, as `crate::routing::Route::auth` fails the sync.
            let maven_39 = config.lock.maven.mode == rv_maven_types::MavenMode::Maven39;
            let url = match transitive && maven_39 && backslash_in_port(&repo.url) {
                true => repo.url.replace('\\', "/"),
                false => repo.url.clone(),
            };
            if secret_url_refusal(&url, repo.url_reads(), secrets, names).is_some()
                || (from != Declaration::LocalPom && expression_id_refusal(config, &repo).is_some())
                || layout_refusal(config, &repo).is_some()
            {
                admission.secret_urls.push(repo);
                continue;
            }
            let admitted = match from {
                Declaration::LocalPom => true,
                // A fetched POM never points raeva at the local file system:
                // its repository is HTTP or HTTPS, or one a mirror serves,
                // as Maven's parent lookup takes one such as
                // `${repo.url}/releases` through the mirror.
                Declaration::RemoteParent => {
                    url::Url::parse(&repo.url)
                        .is_ok_and(|url| matches!(url.scheme(), "http" | "https"))
                        || mirror_serves(config, &repo)
                }
                Declaration::Transitive | Declaration::TransitiveModel => {
                    config.security.allows_transitive_repo_url(&repo.url)
                }
            };
            if admitted {
                admission.admitted.push(repo);
            } else {
                admission.dropped.push(repo);
            }
        }
        admission
    }

    /// Give `repos`, which another client's [`Self::admit`] accepted, what
    /// their provenance allows on this one.
    pub fn grant_admitted(&self, repos: &[Repository]) {
        repos.iter().for_each(|repo| self.grant(repo));
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

/// Whether a mirror that does not block `repo` serves it.
pub fn mirror_serves(config: &Config, repo: &Repository) -> bool {
    matched_mirror(config, repo).is_some_and(|mirror| !mirror.blocked)
}

/// The mirror `repo` goes to, blocking it or not.
pub fn matched_mirror<'a>(
    config: &'a Config,
    repo: &Repository,
) -> Option<&'a rv_config::MirrorConfig> {
    crate::mirror::resolve_mirror(config.mirrors(), repo).1
}

/// Whether the `http` or `https` URL `url` has a `\` after its port
/// separator, which Maven 3.9 reads as part of the port, failing the build
/// on a request to it, where Maven 3.10, as for a `\` elsewhere, fails only
/// the request. A `file://C:\dir` on Windows names a directory.
pub(crate) fn backslash_in_port(url: &str) -> bool {
    (url.split_once("://"))
        .filter(|(scheme, _)| {
            let scheme = scheme.trim_start().to_ascii_lowercase();
            scheme == "http" || scheme == "https"
        })
        .map(|(_, rest)| rest)
        .and_then(|rest| rest.split('/').next())
        .and_then(|authority| authority.rsplit('@').next())
        .and_then(|host_port| host_port.split_once(':'))
        .is_some_and(|(_, port)| port.contains('\\'))
}

/// Why `url` may not be used, as a clause after "its URL", or `None` when
/// it may: [`rv_config::url_refusal`] refuses it, it has a part
/// [`rv_config::secret_url_part`] names, its model looked up a name among
/// `reads` that is a secret's or takes one ([`rv_config::secret_read`], with
/// `names` from [`Config::secret_input_names`]), or the value of one of
/// `secrets` ([`Config::secret_named_inputs`]) is in its path
/// ([`rv_config::url_path_holds`]). The clause names the input, never its
/// value, and says what to do instead.
pub fn secret_url_refusal(
    url: &str,
    reads: &[String],
    secrets: &[(String, String)],
    names: &[(String, String)],
) -> Option<String> {
    rv_config::url_refusal(url).or_else(|| secret_part_refusal(url, reads, secrets, names))
}

/// [`secret_url_refusal`] for the parts of `url` that may hold a secret
/// alone, leaving out [`rv_config::url_refusal`].
pub fn secret_part_refusal(
    url: &str,
    reads: &[String],
    secrets: &[(String, String)],
    names: &[(String, String)],
) -> Option<String> {
    let refused = rv_config::secret_part_refusal(url, false);
    if let Some(part) = rv_config::secret_url_part(url) {
        return Some(format!(
            "has {part}, which {refused}; put credentials in an [[auth]] entry in config.toml \
             or a <server> in settings.xml with the repository's id, not in the URL"
        ));
    }
    let remedy = |input: &str| {
        format!(
            "which {refused}, and that name looks like a secret's; if the value is a token, \
             give the URL with it to a settings.xml <mirror> of the repository, whose URL \
             raeva.lock does not record, or put the credential in a <server> with the \
             repository's id; if it is not a secret, rename {input}"
        )
    };
    if let Some(input) = rv_config::secret_read(reads, names) {
        return Some(format!("takes {input}, {}", remedy(&input)));
    }
    rv_config::secret_input_in_path(url, secrets)
        .map(|input| format!("has the value of {input} in its path, {}", remedy(input)))
}

/// Why a repository id may not be used, as a clause after "its id", or
/// `None` when it may: it takes an input named like a secret, by `reads`
/// and `names` ([`rv_config::secret_read`]), or holds the value of one of
/// `secrets` ([`rv_config::Config::secret_named_inputs`]), as
/// [`rv_config::without_secret_values`] reads it. raeva.lock records an id
/// and messages show it.
pub fn secret_id_refusal(
    id: Option<&str>,
    reads: &[String],
    secrets: &[(String, String)],
    names: &[(String, String)],
) -> Option<String> {
    let id = id?;
    let remedy = |input: &str| {
        format!(
            "which raeva.lock would record and messages show, and that name looks like a \
             secret's; write the id out, or if the value is not a secret, rename {input}"
        )
    };
    if let Some(input) = rv_config::secret_read(reads, names) {
        return Some(format!("takes {input}, {}", remedy(&input)));
    }
    let (input, _) = (secrets.iter())
        .find(|secret| rv_config::without_secret_values(id, std::slice::from_ref(secret)) != id)?;
    Some(format!("has the value of {input}, {}", remedy(input)))
}

/// Why raeva does not read a POM's repository for its `<layout>`,
/// or `None` when the layout is `default` or a mirror serves it: Maven
/// reaches no other layout but through a mirror, as a mirror's
/// `<mirrorOfLayouts>` of `*` serves even one that still holds a `${...}`.
pub fn layout_refusal(config: &Config, repo: &Repository) -> Option<String> {
    let refusal = repo.layout_refusal()?;
    if mirror_serves(config, repo) {
        return None;
    }
    Some(match repo.layout().contains("${") {
        true => format!("<layout> {refusal}, which names no layout Maven reads"),
        false => format!(
            "<layout> {refusal}, which Maven reaches only through a mirror, and none serves it"
        ),
    })
}

/// Why raeva does not follow a POM repository whose `<id>` takes a
/// `${...}`, or `None` when it follows it. Maven matches mirrors and
/// `<server>`s against the id as written while it looks a model's parents
/// up and against the id once interpolated otherwise, as raeva does, so an
/// id raeva fills in as Maven does is followed, one that keeps an undefined
/// property as written too. One that takes an environment variable
/// `[security] allow_env_substitution` does not name, which raeva treats as
/// unset, may take a value in Maven that raeva does not know, and is
/// followed only where no mirror's `<mirrorOf>` names an id and, unless a
/// mirror serves it, no credential does.
pub fn expression_id_refusal(config: &Config, repo: &Repository) -> Option<&'static str> {
    let allowed = &config.security.allow_env_substitution;
    let hidden = (repo.id_reads().iter())
        .filter_map(|read| read.strip_prefix("env."))
        .any(|name| !allowed.iter().any(|allowed| allowed == name));
    if !hidden || !repo.id.as_deref().is_some_and(|id| id.contains("${")) {
        return None;
    }
    let names_ids = (config.mirrors().iter())
        .flat_map(|mirror| &mirror.mirror_of)
        .flat_map(|pattern| pattern.split(','))
        .map(|entry| entry.strip_prefix('!').unwrap_or(entry))
        .any(|entry| !entry.is_empty() && !matches!(entry, "*" | "external:*" | "external:http:*"));
    // Through a mirror, the mirror's id picks the credentials.
    let direct = matched_mirror(config, repo).is_none();
    (names_ids || direct && config.credential_ids().next().is_some()).then_some(
        "takes an environment variable raeva treats as unset, which Maven fills in, while a \
         mirror's <mirrorOf> or a credential names an id; write the id out, or add the \
         variable to [security] allow_env_substitution",
    )
}

/// How messages show a repository `id`: `***` when it takes an input named
/// like a secret, else with each value of `secrets` in it masked.
pub fn shown_id(
    id: &str,
    reads: &[String],
    secrets: &[(String, String)],
    names: &[(String, String)],
) -> String {
    match rv_config::secret_read(reads, names) {
        Some(_) => "***".to_string(),
        None => rv_config::without_secret_values(id, secrets).to_string(),
    }
}

static HTTP_REPO_WARNED: LazyLock<Mutex<HashSet<(String, bool)>>> = LazyLock::new(Mutex::default);

/// Refuse external HTTP declared by a POM unless `raeva.toml` or
/// `config.toml` names the URL as a repository, or the mirror that matches
/// it is not blocked, or, with none, replaced Maven's default HTTP blocker,
/// as with that blocker, which blocks a settings.xml repository too.
/// `project` tells whether the project or its parents declared it, which
/// raeva reports without `-v`.
pub(crate) fn http_repository_blocked(config: &Config, repo: &Repository, project: bool) -> bool {
    if !url::Url::parse(&repo.url).is_ok_and(|url| url.scheme() == "http")
        || !crate::mirror::is_external_http_repo(&repo.url)
        || crate::mirror::own_urls(config)
            .contains(&crate::repository::normalize_repo_url(&repo.url))
        || match crate::mirror::resolve_mirror(config.mirrors(), repo).1 {
            Some(mirror) => !mirror.blocked,
            None => !crate::mirror::http_blocker_applies(config.mirrors()),
        }
    {
        return false;
    }
    let key = (crate::repository::normalize_repo_url(&repo.url), project);
    let url = rv_config::redact_repository_url(&repo.url);
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
                 the URL in raeva.toml or config.toml"
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

    use super::{Declaration, Provenance, RepositoryPolicy, secret_id_refusal};
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

    /// Repositories one client admitted get the same trust on another.
    #[test]
    fn admitted_repositories_carry_their_trust_to_another_client() {
        let (first, _) = policy(&["https://allowed.example/"]);
        let (second, transport) = policy(&["https://allowed.example/"]);
        let local = first.admit(repos(&["https://nexus.corp/m2/"]), Declaration::LocalPom);
        let fetched = first.admit(
            repos(&["https://allowed.example/m2/", "https://other.example/m2/"]),
            Declaration::RemoteParent,
        );
        second.grant_admitted(&[local.admitted, fetched.admitted].concat());
        assert!(trusts(&transport, "https://nexus.corp/"));
        assert!(transport.authorizes_issuer("https://nexus.corp/"));
        assert!(trusts(&transport, "https://allowed.example/"));
        assert!(!transport.authorizes_issuer("https://allowed.example/"));
        assert!(!trusts(&transport, "https://other.example/"));
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
    fn an_id_holding_a_secret_named_value_is_refused() {
        let secrets = [("-Dcs.token".to_string(), "s3cretpass".to_string())];
        let refusal = secret_id_refusal(Some("s3cretpass"), &[], &secrets, &[]).expect("refused");
        assert!(
            refusal.starts_with("has the value of -Dcs.token,"),
            "{refusal}"
        );
        assert!(!refusal.contains("s3cretpass"), "{refusal}");
        for id in [None, Some("corp"), Some("")] {
            assert_eq!(secret_id_refusal(id, &[], &secrets, &[]), None, "{id:?}");
        }
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
    fn a_backslash_before_localhost_does_not_bypass_the_http_blocker() {
        let config = config(SecurityConfig::default());
        let repository = repo(r"http://repo.example\@localhost/maven2/");
        assert!(super::http_repository_blocked(&config, &repository, true));
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
                // Maven's blocker spares `localhost` and `127.0.0.1` only,
                // as the URL spells them.
                for url in [
                    "http://[::1]:8080/",
                    "http://LOCALHOST:8080/",
                    "http://127.1:8080/",
                    "http://0x7f.0.0.1/",
                ] {
                    let admission = policy.admit([repo(url)], from);
                    assert_eq!(admission.blocked_http, [repo(url)], "{url}");
                }
                for url in [
                    "http://127.0.0.1:8080/",
                    "http://localhost:8080/",
                    "https://repo.example/",
                ] {
                    assert_eq!(policy.admit([repo(url)], from).admitted, [repo(url)]);
                }
            }
        });
        // Once per URL for the project and its parents, and once for
        // dependencies, which raeva shows only at -v.
        assert_eq!(output.matches("HTTP_REPO_BLOCKED").count(), 10, "{output}");
        assert_eq!(output.matches("project=true").count(), 5, "{output}");
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
        // A user mirror that takes the blocker's id replaces it, as in
        // Maven's settings merge, whatever it mirrors.
        let mut unblocked =
            rv_config::MirrorConfig::new(Some("maven-default-http-blocker"), "http://0.0.0.0/");
        unblocked.mirror_of = vec!["none".into()];
        let unblocked = config.clone().with_mirrors(vec![unblocked]);
        let mut excluded = rv_config::MirrorConfig::new(Some("safe"), "https://mirror.example/");
        excluded.mirror_of = vec!["external:http:*,!legacy".into()];
        let excluded = config.clone().with_mirrors(vec![excluded]);
        // A blocked mirror with the blocker's id blocks what it mirrors.
        let mut own_blocker =
            rv_config::MirrorConfig::new(Some("maven-default-http-blocker"), "http://0.0.0.0/");
        own_blocker.mirror_of = vec!["external:http:*,!legacy".into()];
        own_blocker.blocked = true;
        let own_blocker = config.clone().with_mirrors(vec![own_blocker]);
        // A blocked mirror of the user's blocks it as Maven's blocker does:
        // admitted, a `central` would replace the default Central.
        let mut blocked = rv_config::MirrorConfig::new(Some("no-http"), "http://0.0.0.0/");
        blocked.mirror_of = vec!["external:http:*".into()];
        blocked.blocked = true;
        let blocked = config.with_mirrors(vec![blocked]);
        let legacy = Repository::new(Some("legacy".into()), "http://repo.example/", true, false);
        for config in [configured, mirrored, unblocked, own_blocker.clone()] {
            assert_eq!(
                RepositoryPolicy::screen(&config, [legacy.clone()], Declaration::LocalPom).admitted,
                std::slice::from_ref(&legacy)
            );
        }
        let other = Repository::new(Some("other".into()), "http://repo.example/", true, false);
        for (config, repo) in [
            (excluded, &legacy),
            (blocked, &legacy),
            (own_blocker, &other),
        ] {
            assert!(
                RepositoryPolicy::screen(&config, [repo.clone()], Declaration::LocalPom)
                    .admitted
                    .is_empty()
            );
        }
    }

    /// Maven's default HTTP blocker blocks the plugin repositories of
    /// settings.xml on plain HTTP too: of a profile active by
    /// `<activeProfiles>` and of one active by `<activation>`.
    #[test]
    fn a_settings_plugin_repository_url_stays_blocked() {
        let home = tempfile::tempdir().unwrap();
        let project = home.path().join("project");
        let raeva_home = home.path().join("raeva");
        for dir in [&project, &raeva_home, &home.path().join(".m2")] {
            std::fs::create_dir_all(dir).unwrap();
        }
        let profile = |id: &str, activation: &str| {
            format!(
                "<profile><id>{id}</id>{activation}<pluginRepositories><pluginRepository>\
                 <id>{id}</id><url>http://{id}.example/</url></pluginRepository>\
                 </pluginRepositories></profile>"
            )
        };
        std::fs::write(
            home.path().join(".m2/settings.xml"),
            format!(
                "<settings><profiles>{}{}</profiles><activeProfiles>\
                 <activeProfile>named</activeProfile></activeProfiles></settings>",
                profile("named", ""),
                profile(
                    "activated",
                    "<activation><activeByDefault>true</activeByDefault></activation>"
                ),
            ),
        )
        .unwrap();
        temp_env::with_vars(
            [
                ("HOME", Some(home.path().as_os_str())),
                ("USERPROFILE", Some(home.path().as_os_str())),
                (
                    rv_config::MAVEN_USER_HOME_TEST_ENV,
                    Some(home.path().as_os_str()),
                ),
                ("RAEVA_HOME", Some(raeva_home.as_os_str())),
            ],
            || {
                let config = Config::load(&project).unwrap();
                for url in [
                    "http://named.example/",
                    "http://activated.example/",
                    "http://other.example/",
                ] {
                    assert!(
                        super::http_repository_blocked(&config, &repo(url), true),
                        "{url}"
                    );
                }
            },
        );
    }

    #[test]
    fn provenance_is_not_part_of_equality() {
        let mut pom = rv_maven_model::Repository::new(None, "https://repo.example/");
        pom.snapshots_enabled = false;
        assert_eq!(Repository::from(pom), repo("https://repo.example/"));
    }
}
