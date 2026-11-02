use std::collections::HashSet;
use std::io;
use std::path::Path;
use std::time::Duration;

use clap::Args;

use rv_config::{AuthConfig, Config};
use rv_maven_types::Coord;
use rv_repo::{RepoClient, RepoError, Repository, normalize_repo_url};

use crate::error::{CliError, ErrorClass, ExitStatus, Result, report};
use crate::output::{CommandOutput, Human, Report, Table};
use crate::session::Session;

const DOCTOR_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Args)]
#[command(after_long_help = crate::commands::util::help_examples(&[
    ("doctor", "Check the store and every repository"),
    ("--json doctor", "Output as JSON"),
]))]
pub(crate) struct DoctorArgs {}

struct Row {
    check: String,
    details: String,
    outcome: Outcome,
}

impl Row {
    fn new(check: impl Into<String>, details: impl Into<String>, outcome: Outcome) -> Self {
        Self {
            check: check.into(),
            details: details.into(),
            outcome,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Ok,
    Inconclusive,
    /// Context for reading the other rows, never a pass or a failure.
    Info,
    /// Trust roots, repository URLs, the store directory.
    Config,
    /// 401, 403 or 407.
    Auth,
    /// Timeout, DNS, connection failure, server 5xx.
    Network,
    Other,
}

impl Outcome {
    fn status(self) -> &'static str {
        match self {
            Outcome::Ok => "ok",
            Outcome::Inconclusive => "inconclusive",
            Outcome::Info => "info",
            Outcome::Config | Outcome::Auth | Outcome::Network | Outcome::Other => "fail",
        }
    }

    fn class(self) -> Option<&'static str> {
        match self {
            Outcome::Config => Some("config"),
            Outcome::Auth => Some("auth"),
            Outcome::Network => Some("network"),
            Outcome::Other => Some("other"),
            Outcome::Ok | Outcome::Inconclusive | Outcome::Info => None,
        }
    }

    fn is_failure(self) -> bool {
        self.class().is_some()
    }

    fn from_class(class: ErrorClass) -> Self {
        match class {
            ErrorClass::Auth | ErrorClass::ProxyAuth => Outcome::Auth,
            ErrorClass::Network => Outcome::Network,
            ErrorClass::Tls | ErrorClass::Config | ErrorClass::Lockfile => Outcome::Config,
            ErrorClass::NotFound => Outcome::Inconclusive,
            ErrorClass::Integrity(_)
            | ErrorClass::Store
            | ErrorClass::Offline
            | ErrorClass::Other => Outcome::Other,
        }
    }
}

pub(crate) async fn run(_args: &DoctorArgs, session: &Session) -> Result<Report> {
    session.require_network("doctor", "checks repository connectivity")?;
    let config = session.config_async().await?;
    let mut rows = vec![trust_roots_row(), store_row(&config.paths.store_dir)];

    // A real `RepoClient` applies what a sync applies: mirrors, credentials,
    // proxies and the redirect policy.
    match build_probe_client(&config).await {
        Ok((client, _cache_guard)) => probe_all(&config, &client, &mut rows).await,
        Err(err) => rows.push(Row::new(
            "repository client",
            format!(
                "{err} (check the proxy and credential configuration in config.toml, \
                 raeva.toml and settings.xml, and the proxy variables)"
            ),
            Outcome::Config,
        )),
    }

    let failed = rows.iter().filter(|row| row.outcome.is_failure()).count();
    let status = classify_exit_code(&rows);
    let report = Report::data(DoctorReport { rows });
    if failed > 0 {
        Ok(report.failed(CliError::DoctorChecksFailed { failed, status }))
    } else {
        Ok(report)
    }
}

struct DoctorReport {
    rows: Vec<Row>,
}

impl CommandOutput for DoctorReport {
    fn to_json(&self) -> serde_json::Result<serde_json::Value> {
        let checks: Vec<_> = self
            .rows
            .iter()
            .map(|row| {
                serde_json::json!({
                    "check": row.check,
                    "status": row.outcome.status(),
                    "class": row.outcome.class(),
                    "details": row.details,
                })
            })
            .collect();
        Ok(serde_json::json!({
            "issues": self.rows.iter().filter(|row| row.outcome.is_failure()).count(),
            "checks": checks,
        }))
    }

    fn render_human(&self, human: &mut Human<'_>) -> io::Result<()> {
        human.heading("doctor results")?;
        let mut table = Table::new(["Check", "Status", "Details"]);
        for row in &self.rows {
            table.add_row([&row.check, row.outcome.status(), &row.details]);
        }
        human.fitted_table(&table)?;
        let inconclusive = (self.rows.iter())
            .filter(|row| row.outcome == Outcome::Inconclusive)
            .count();
        if inconclusive > 0 {
            human.note(format!(
                "{inconclusive} inconclusive, which is not a pass, though raeva doctor exits 0 \
                 when no check fails"
            ))?;
        }
        Ok(())
    }
}

/// Where TLS trust comes from, so a certificate failure below can be read
/// against it.
fn trust_roots_row() -> Row {
    let details = match rv_http::trust_roots() {
        rv_http::TrustRoots::Platform => "operating system trust store".to_string(),
        rv_http::TrustRoots::Empty => {
            "no system trust roots found, so HTTPS repositories cannot be verified \
             (install your distribution's CA certificates or set SSL_CERT_FILE)"
                .to_string()
        }
        rv_http::TrustRoots::Environment { certificates } => format!(
            "{certificates} certificate(s) from SSL_CERT_FILE/SSL_CERT_DIR, which replace \
             the system trust store"
        ),
        _ => "unrecognized trust root source".to_string(),
    };
    Row::new("TLS trust roots", details, Outcome::Info)
}

/// Where sync keeps downloads, and whether raeva can write there. A store that
/// does not exist yet is checked at its nearest existing parent.
fn store_row(store: &Path) -> Row {
    const CHECK: &str = "store directory";
    let existing = store.ancestors().find(|dir| dir.exists()).unwrap_or(store);
    match tempfile::tempfile_in(existing) {
        Ok(_) => Row::new(CHECK, store.display().to_string(), Outcome::Info),
        Err(err) => Row::new(
            CHECK,
            format!(
                "cannot write to {}: {err} (check its permissions, or set RAEVA_HOME)",
                existing.display()
            ),
            Outcome::Config,
        ),
    }
}

/// A client whose metadata cache is a throwaway directory, so every probe
/// goes to the network, with one attempt and a bounded timeout. The
/// `TempDir` must outlive the client.
async fn build_probe_client(config: &Config) -> Result<(RepoClient, tempfile::TempDir)> {
    let cache_dir = tempfile::tempdir().map_err(CliError::io_at(std::env::temp_dir()))?;
    let mut probe_config = config.clone();
    probe_config.paths.store_dir = cache_dir.path().join("store");
    probe_config.network.timeout = DOCTOR_REQUEST_TIMEOUT.as_secs();
    probe_config.network.retries = 0;
    let client = RepoClient::new(&probe_config)
        .await?
        .with_allow_missing_checksums(true);
    Ok((client, cache_dir))
}

struct ProbeTarget {
    repository: Repository,
    declared_in: Option<String>,
}

async fn probe_all(config: &Config, client: &RepoClient, rows: &mut Vec<Row>) {
    let (declared, replaced, project_row) = match project_repositories(config, client) {
        Ok((declared, replaced)) => (declared, replaced, None),
        Err(row) => (Vec::new(), HashSet::new(), Some(row)),
    };
    let mut targets: Vec<ProbeTarget> = config
        .repositories()
        .iter()
        .filter(|repo| !replaced.contains(&normalize_repo_url(&repo.url)))
        .map(|repo| ProbeTarget {
            repository: Repository::from(repo),
            declared_in: None,
        })
        .collect();
    let mut refused_rows = Vec::new();
    // Sync trusts these as the user's own declarations, and refuses a URL
    // with userinfo, a query or a fragment, or plain HTTP to another host.
    // Doctor must too: admit screens those out, and only admitted targets
    // are probed.
    let repositories: Vec<Repository> = declared.iter().map(|t| t.repository.clone()).collect();
    let admission = client
        .policy()
        .admit(repositories, rv_repo::Declaration::LocalPom);
    let declared_in: std::collections::HashMap<String, String> = declared
        .into_iter()
        .filter_map(|target| {
            target
                .declared_in
                .map(|path| (normalize_repo_url(&target.repository.url), path))
        })
        .collect();
    let secrets = config.secret_named_inputs();
    let refused = |repo: &Repository| {
        let path = declared_in
            .get(&normalize_repo_url(&repo.url))
            .map_or("pom.xml", String::as_str);
        let label = repo.id.as_deref().unwrap_or("repository");
        let label = rv_config::without_secret_values(label, &secrets);
        (format!("{label} ({path})"), path.to_string())
    };
    for repo in &admission.secret_urls {
        let Some(refusal) = rv_repo::secret_url_refusal(&repo.url, &secrets) else {
            continue;
        };
        let (label, path) = refused(repo);
        refused_rows.push(Row::new(
            label,
            format!("a <repository> URL declared in {path} {refusal}"),
            Outcome::Config,
        ));
    }
    for repo in &admission.blocked_http {
        refused_rows.push(Row::new(
            refused(repo).0,
            "plain HTTP, which sync ignores, as Maven's HTTP blocker does; name the same \
             URL in raeva.toml, config.toml or settings.xml, or a mirror for it, to use it",
            Outcome::Inconclusive,
        ));
    }
    targets.extend(admission.admitted.into_iter().map(|repository| {
        let key = normalize_repo_url(&repository.url);
        ProbeTarget {
            declared_in: declared_in.get(&key).cloned(),
            repository,
        }
    }));
    let user_origins: HashSet<String> = config
        .user_endpoint_urls()
        .iter()
        .map(|url| http_origin(url))
        .filter(|origin| !origin.is_empty())
        .collect();
    rows.extend(
        futures::future::join_all(
            (targets.iter()).map(|target| probe(config, client, target, &user_origins)),
        )
        .await,
    );
    rows.extend(refused_rows);
    rows.extend(project_row);
}

/// Repositories the project's own POMs declare that configuration does not
/// already name, in reactor order and deduplicated by URL, and the URLs of
/// the defaults sync never asks: every module of every `[lock] jdks` target
/// declares a repository `client` admits under the default's id, as one
/// under `central` replaces the super POM's. A missing or unreadable
/// `pom.xml` yields a row instead.
fn project_repositories(
    config: &Config,
    client: &RepoClient,
) -> std::result::Result<(Vec<ProbeTarget>, HashSet<String>), Row> {
    const CHECK: &str = "project repositories";
    if !config.project_root.join("pom.xml").is_file() {
        return Err(Row::new(
            CHECK,
            "no pom.xml in the project directory; only configured repositories were probed",
            Outcome::Info,
        ));
    }
    let targets = crate::commands::project_declared_repositories(config).map_err(|err| {
        Row::new(
            CHECK,
            format!(
                "pom.xml could not be read, so the repositories it declares were not probed: \
                 {err}"
            ),
            Outcome::Config,
        )
    })?;

    let defaults = config.default_repositories();
    let replaces = |default: &rv_config::RepoConfig, repository: &Repository| {
        repository.id == default.id
            && !defaults.iter().any(|other| other.url == repository.url)
            && (client.policy())
                .admit([repository.clone()], rv_repo::Declaration::LocalPom)
                .admitted
                .len()
                == 1
    };
    let replaced = defaults
        .iter()
        .filter(|default| {
            default.id.is_some()
                && (targets.iter().flatten()).all(|(_, declared)| {
                    declared
                        .iter()
                        .any(|repository| replaces(default, repository))
                })
        })
        .map(|default| normalize_repo_url(&default.url))
        .collect();
    let mut declared = Vec::new();
    for (path, repositories) in targets.into_iter().flatten() {
        for repository in repositories {
            let entry = (repository, path.clone());
            if !declared.contains(&entry) {
                declared.push(entry);
            }
        }
    }
    let mut seen: HashSet<String> = config
        .repositories()
        .iter()
        .map(|repo| normalize_repo_url(&repo.url))
        .collect();
    let declared = declared
        .into_iter()
        .filter(|(repository, _)| seen.insert(normalize_repo_url(&repository.url)))
        .map(|(repository, pom_path)| ProbeTarget {
            repository,
            declared_in: Some(pom_path),
        })
        .collect();
    Ok((declared, replaced))
}

/// Fetch the probe file's metadata the way a sync would, through any mirror
/// and with the credential sync would send.
async fn probe(
    config: &Config,
    client: &RepoClient,
    target: &ProbeTarget,
    user_origins: &HashSet<String>,
) -> Row {
    let origin = &target.repository;
    let route = client.route(origin);
    let mut label = origin
        .id
        .clone()
        .unwrap_or_else(|| "repository".to_string());
    let mirror = route
        .mirror
        .as_ref()
        .map(|mirror| format!("via mirror {}", mirror.id.as_deref().unwrap_or("<unnamed>")));
    let notes: Vec<String> = target.declared_in.iter().cloned().chain(mirror).collect();
    if !notes.is_empty() {
        label.push_str(&format!(" ({})", notes.join(", ")));
    }

    if let Err(err) = route.endpoint.base_url() {
        let declared_by = target.declared_in.as_deref().unwrap_or("raeva.toml");
        return Row::new(
            label,
            format!("{err} (check repository URL in {declared_by})"),
            Outcome::Config,
        );
    }
    let Some(coord) = probe_coord(origin) else {
        return Row::new(
            label,
            "repository has both releases and snapshots disabled",
            Outcome::Config,
        );
    };
    if let Ok(url) = route.endpoint.base_url()
        && url.scheme() == "file"
        && let Some(dir) = rv_lock::file_url_path(&url)
        && !dir.is_dir()
    {
        return Row::new(
            label,
            format!("{} is not a directory", dir.display()),
            Outcome::Config,
        );
    }
    let path = probe_metadata_path(&coord);
    let credential = credential_source(
        config.auth(),
        &route.endpoint,
        route.cross_origin || !user_origins.contains(&http_origin(&route.endpoint.url)),
    );
    let (details, outcome) = match client.fetch_metadata(origin, &coord).await {
        Ok(_) => match &credential {
            Some(credential) => (
                format!("served {path} with {}", credential.label()),
                Outcome::Ok,
            ),
            None => (format!("served {path}"), Outcome::Ok),
        },
        Err(err) => {
            let settings = crate::error::HintEnv::for_config(config).settings_location();
            classify_probe_error(err, &route.endpoint, &path, &settings, credential.as_ref())
        }
    };
    Row::new(label, details, outcome)
}

/// Where the credential the probe attached came from. Source only: secret
/// values are never read.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CredentialSource {
    ConfigId(String),
    ConfigDefault,
}

impl CredentialSource {
    fn label(&self) -> String {
        match self {
            Self::ConfigId(id) => format!("credentials for id '{id}'"),
            Self::ConfigDefault => "default credentials".to_string(),
        }
    }
}

/// The credential sync would attach to the resolved repository, in
/// rv-repo's `AuthStore` precedence: an entry for its id, then the default
/// entry unless `withhold_default`. Sync withholds the default from a mirror
/// on another host than the repository it replaced, and from an origin that
/// no repository or mirror in config.toml or settings.xml names.
fn credential_source(
    auth: &[AuthConfig],
    resolved: &Repository,
    withhold_default: bool,
) -> Option<CredentialSource> {
    // A `file:` repository is read from disk, with no credential.
    if resolved
        .url
        .get(..5)
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("file:"))
    {
        return None;
    }
    let usable = |entry: &&AuthConfig| {
        entry.token.is_some() || (entry.username.is_some() && entry.password.is_some())
    };
    if let Some(id) = resolved.id.as_deref()
        && auth
            .iter()
            .filter(usable)
            .any(|entry| entry.id.as_deref() == Some(id))
    {
        return Some(CredentialSource::ConfigId(id.to_string()));
    }
    if withhold_default {
        return None;
    }
    auth.iter()
        .filter(usable)
        .find(|entry| entry.id.is_none())
        .map(|_| CredentialSource::ConfigDefault)
}

fn http_origin(url: &str) -> String {
    url::Url::parse(url.trim())
        .ok()
        .filter(|url| matches!(url.scheme(), "http" | "https"))
        .map(|url| url.origin().ascii_serialization())
        .unwrap_or_default()
}

/// `org.apache:maven`, whose metadata Maven Central has always served, as a
/// release or, for a snapshot-only repository, a snapshot. On a private
/// repository it usually 404s, which leaves the row inconclusive while
/// connectivity, TLS, proxy and auth failures still show.
fn probe_coord(repo: &Repository) -> Option<Coord> {
    let version = if repo.releases_enabled {
        "1.0"
    } else if repo.snapshots_enabled {
        "1.0-SNAPSHOT"
    } else {
        return None;
    };
    Coord::parse(&format!("org.apache:maven:{version}")).ok()
}

fn probe_metadata_path(coord: &Coord) -> String {
    let base = format!(
        "{}/{}",
        coord.group_id.as_str().replace('.', "/"),
        coord.artifact_id.as_str()
    );
    let version = coord.version.to_string();
    if version.ends_with("-SNAPSHOT") {
        format!("{base}/{version}/maven-metadata.xml")
    } else {
        format!("{base}/maven-metadata.xml")
    }
}

/// The details and outcome of a failed probe. For a 401 or 403, the hint
/// tells "nothing was sent" from "credentials were sent and rejected"; a
/// 404 says whether `credential` was sent, as some repositories answer a
/// wrong one with 404.
fn classify_probe_error(
    err: RepoError,
    resolved: &Repository,
    path: &str,
    settings: &str,
    credential: Option<&CredentialSource>,
) -> (String, Outcome) {
    let sent = match &err {
        RepoError::Unauthorized { sent, .. } => sent.as_deref(),
        _ => None,
    };
    match err.status_code() {
        Some(code @ (401 | 403)) => {
            let details = match sent {
                Some(sent) => {
                    let label = report::credential_label(sent.id.as_deref());
                    let file = report::credential_file(sent.file, settings);
                    if let Some(note) = report::unset_variables_note(&sent.unset_variables) {
                        format!("{code} ({label} were sent but rejected; {note} from {file})")
                    } else {
                        format!(
                            "{code} ({label} were sent but rejected; check the username/password \
                             or token in {file})"
                        )
                    }
                }
                None => format!(
                    "{code} (no credentials were sent; {})",
                    missing_credential_hint(resolved, settings)
                ),
            };
            (details, Outcome::Auth)
        }
        Some(407) => (
            "407 (proxy authentication required; check proxy credentials)".to_string(),
            Outcome::Auth,
        ),
        Some(404) => {
            let (sent, unchecked) = match credential {
                Some(credential) => (
                    format!("{} were sent", credential.label()),
                    "neither the repository's content nor the credentials are checked",
                ),
                None => (
                    "no credentials were sent".to_string(),
                    "the repository's content is not checked",
                ),
            };
            (
                format!(
                    "404 for the org.apache:maven metadata at {path} ({sent}), so {unchecked}; \
                     run raeva sync with a dependency that lives there"
                ),
                Outcome::Inconclusive,
            )
        }
        Some(code) if (500..600).contains(&code) => (
            format!("{code} (repository server error, try again later)"),
            Outcome::Network,
        ),
        _ => match err {
            RepoError::Http(http_err) => {
                // An untrusted certificate is configuration; other TLS
                // failures stay network.
                let outcome = if rv_http::tls_cause(&http_err)
                    .is_some_and(rv_http::tls_failure_is_permanent)
                {
                    Outcome::Config
                } else {
                    Outcome::Network
                };
                (format_connection_error(http_err), outcome)
            }
            other => {
                let outcome = Outcome::from_class(ErrorClass::of(&other));
                (other.to_string(), outcome)
            }
        },
    }
}

/// Where to put the credential a probe did not send. Secrets never belong in
/// the project raeva.toml, which is usually committed.
fn missing_credential_hint(resolved: &Repository, settings: &str) -> String {
    match resolved
        .id
        .as_deref()
        .filter(|id| !id.chars().any(char::is_control))
    {
        Some(id) => format!("add a <server> entry with id '{id}' to {settings}"),
        None => format!("configure credentials in {settings} or the user config.toml"),
    }
}

fn classify_exit_code(rows: &[Row]) -> ExitStatus {
    let failures: Vec<Outcome> = rows
        .iter()
        .map(|row| row.outcome)
        .filter(|outcome| outcome.is_failure())
        .collect();
    if failures.is_empty() {
        ExitStatus::Success
    } else if rows.iter().any(|row| row.outcome == Outcome::Ok) {
        ExitStatus::Partial
    } else if failures
        .iter()
        .all(|outcome| matches!(outcome, Outcome::Auth | Outcome::Config))
    {
        ExitStatus::Config
    } else if failures.iter().all(|outcome| *outcome == Outcome::Network) {
        ExitStatus::Network
    } else {
        ExitStatus::Failure
    }
}

fn format_connection_error(err: reqwest::Error) -> String {
    // Only the source chain names a TLS handshake failure.
    let tls = rv_http::tls_cause(&err).map(rv_http::describe_tls_failure);
    // The URL may carry userinfo.
    let safe = err.without_url();
    if safe.is_timeout() {
        return format!("{safe} (connection or response too slow; check network latency)");
    }
    if let Some(tls) = tls {
        let remedy = match rv_http::trust_roots() {
            rv_http::TrustRoots::Environment { .. } => {
                "add its CA to SSL_CERT_FILE or SSL_CERT_DIR, which replace the OS trust store"
            }
            _ => "install its CA into your OS trust store",
        };
        return format!(
            "{safe} (TLS failed: {tls}; if the server certificate is not trusted, {remedy})"
        );
    }
    if safe.is_connect() {
        let cause = rv_http::transient::transport_detail(&safe)
            .map(|cause| format!(": {cause}"))
            .unwrap_or_default();
        return format!(
            "{safe}{cause} (cannot establish connection; verify URL, network, and firewall)"
        );
    }
    if safe.is_request() {
        return format!("{safe} (request failed; check proxy and firewall settings)");
    }
    safe.to_string()
}

#[cfg(test)]
mod tests {
    use super::{CredentialSource, Outcome, Row, classify_exit_code, credential_source};
    use crate::error::ExitStatus;
    use rv_config::AuthConfig;
    use rv_repo::Repository;
    use rv_test_support::http::{Response, StubServer};

    fn config_in(root: &std::path::Path, file: &str, contents: &str) -> rv_config::Config {
        std::fs::write(root.join(file), contents).expect("write config");
        temp_env::with_vars(
            [
                ("HOME", Some(root)),
                ("USERPROFILE", Some(root)),
                ("RAEVA_HOME", Some(root)),
            ],
            || rv_config::Config::load(root).expect("config"),
        )
    }

    async fn probe_project(root: &std::path::Path, file: &str, configured: &str) -> Vec<Row> {
        let config = config_in(root, file, configured);
        let (client, _cache) = super::build_probe_client(&config)
            .await
            .expect("probe client");
        let mut rows = Vec::new();
        super::probe_all(&config, &client, &mut rows).await;
        rows
    }

    fn pom(id: &str, repositories: &str, modules: &str) -> String {
        format!(
            r#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>{id}</artifactId>
  <version>1.0</version>
  <packaging>pom</packaging>
  <modules>{modules}</modules>
  <repositories>{repositories}</repositories>
</project>
"#
        )
    }

    fn pom_repository(id: &str, url: &str) -> String {
        format!("<repository><id>{id}</id><url>{url}</url></repository>")
    }

    /// A raeva.toml entry that points Central at `server`, so the probe
    /// reaches no real host.
    fn local_central(server: &StubServer) -> String {
        format!(
            "\n[[repositories]]\nid = \"central\"\nurl = \"http://{}/central/\"\n",
            server.addr()
        )
    }

    /// A default credential that sync withholds, here from a repository only
    /// raeva.toml names, is not reported as sent. Named in config.toml, the
    /// same repository gets it.
    #[tokio::test]
    async fn a_withheld_default_credential_is_not_reported_as_sent() {
        for (file, sent) in [("raeva.toml", false), ("config.toml", true)] {
            let authorized = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let seen = authorized.clone();
            let server = StubServer::start(move |request| {
                if request.header("authorization").is_some() {
                    seen.store(true, std::sync::atomic::Ordering::SeqCst);
                    Response::new(403, "")
                } else {
                    Response::new(401, "")
                }
            });
            let central = StubServer::start(|_| Response::new(404, ""));
            let root = tempfile::tempdir().expect("tempdir");
            let rows = probe_project(
                root.path(),
                file,
                &format!(
                    "[[repositories]]\nid = \"corp\"\nurl = \"http://{}/repo/\"\n{}\n\
                     [[auth]]\nusername = \"u\"\npassword = \"p\"\n",
                    server.addr(),
                    local_central(&central),
                ),
            )
            .await;
            server.stop();
            assert_eq!(
                authorized.load(std::sync::atomic::Ordering::SeqCst),
                sent,
                "{file}"
            );
            let details = &rows[0].details;
            assert_eq!(rows[0].outcome, Outcome::Auth, "{file}: {details}");
            assert_eq!(
                details.contains("default credentials were sent but rejected"),
                sent,
                "{file}: {details}"
            );
        }
    }

    /// A 404 for the probe file checks nothing, since some repositories
    /// answer a wrong credential with 404 too: the row says whether
    /// credentials were sent and how to check the repository instead.
    #[tokio::test]
    async fn a_404_says_what_it_leaves_unchecked() {
        let server = StubServer::start(|_| Response::new(404, ""));
        let root = tempfile::tempdir().expect("tempdir");
        let rows = probe_project(
            root.path(),
            "config.toml",
            &format!(
                "[[repositories]]\nid = \"corp\"\nurl = \"http://{0}/corp/\"\n\
                 [[repositories]]\nid = \"open\"\nurl = \"http://{0}/open/\"\n{1}\n\
                 [[auth]]\nid = \"corp\"\ntoken = \"t\"\n",
                server.addr(),
                local_central(&server),
            ),
        )
        .await;
        server.stop();
        let path = "org/apache/maven/maven-metadata.xml";
        for (id, expected) in [
            (
                "corp",
                format!(
                    "404 for the org.apache:maven metadata at {path} (credentials for id \
                     'corp' were sent), so neither the repository's content nor the \
                     credentials are checked; run raeva sync with a dependency that lives there"
                ),
            ),
            (
                "open",
                format!(
                    "404 for the org.apache:maven metadata at {path} (no credentials were \
                     sent), so the repository's content is not checked; run raeva sync with a \
                     dependency that lives there"
                ),
            ),
        ] {
            let row = (rows.iter())
                .find(|row| row.check.starts_with(id))
                .unwrap_or_else(|| panic!("no {id} row"));
            assert_eq!(row.outcome, Outcome::Inconclusive, "{}", row.details);
            assert_eq!(row.details, expected);
        }
    }

    /// Sync refuses a POM repository URL with userinfo before any fetch.
    /// Doctor must do the same: a Config row that names the POM, never the
    /// secret, and no request to that host.
    #[tokio::test]
    async fn a_pom_repository_url_with_userinfo_is_not_probed() {
        let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = hits.clone();
        let server = StubServer::start(move |_request| {
            seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Response::new(404, "")
        });
        let secret_url = format!(
            "http://alice:hunter2@{}/maven2/?api_key=topsecretvalue",
            server.addr()
        );
        let root = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            root.path().join("pom.xml"),
            pom("app", &pom_repository("leaky", &secret_url), ""),
        )
        .expect("write pom.xml");
        let central = StubServer::start(|_| Response::new(404, ""));
        let rows = probe_project(root.path(), "raeva.toml", &local_central(&central)).await;
        server.stop();
        assert_eq!(
            hits.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "doctor contacted the secret URL"
        );
        let leaky = rows
            .iter()
            .find(|row| row.check.contains("leaky"))
            .expect("leaky row");
        assert_eq!(leaky.outcome, Outcome::Config, "{}", leaky.details);
        assert!(
            leaky.details.contains("userinfo") && leaky.details.contains("pom.xml"),
            "{}",
            leaky.details
        );
        let combined = rows
            .iter()
            .map(|row| format!("{} {}", row.check, row.details))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!combined.contains("hunter2"), "{combined}");
        assert!(!combined.contains("topsecretvalue"), "{combined}");
    }

    /// The repository sync fails on is often the one `pom.xml` declares, so
    /// doctor probes it with the same client and credential policy and shows
    /// the missing credential on its own row.
    #[tokio::test]
    async fn pom_repository_that_answers_401_is_a_failing_row() {
        let server = StubServer::start(|request| {
            if request.path.starts_with("/canary/") {
                Response::new(401, "")
            } else {
                Response::new(404, "")
            }
        });
        let base = format!("http://{}", server.addr());
        let root = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(root.path().join("child")).expect("child dir");
        std::fs::write(
            root.path().join("pom.xml"),
            pom(
                "app",
                &format!(
                    "{}{}",
                    pom_repository("raeva", &format!("{base}/canary/")),
                    pom_repository("local", &format!("{base}/empty/"))
                ),
                "<module>child</module>",
            ),
        )
        .expect("write pom.xml");
        std::fs::write(
            root.path().join("child").join("pom.xml"),
            pom(
                "child",
                &pom_repository("module-repo", &format!("{base}/module/")),
                "",
            ),
        )
        .expect("write child pom.xml");

        // Central is kept beside configured repositories; this one stands in
        // for it.
        let configured = format!(
            "[[repositories]]\nid = \"local\"\nurl = \"{base}/empty/\"\n\
             [[repositories]]\nid = \"central\"\nurl = \"{base}/central/\"\n"
        );
        let rows = probe_project(root.path(), "raeva.toml", &configured).await;
        let checks: Vec<&str> = rows.iter().map(|row| row.check.as_str()).collect();
        assert_eq!(
            checks,
            [
                "local",
                "central",
                "raeva (pom.xml)",
                "module-repo (child/pom.xml)"
            ],
            "a configured URL is probed once"
        );
        let raeva = &rows[2];
        assert_eq!(raeva.outcome, Outcome::Auth);
        assert!(
            raeva.details.starts_with("401 (no credentials were sent")
                && raeva.details.contains("id 'raeva'"),
            "{}",
            raeva.details
        );
        assert_eq!(rows[3].outcome, Outcome::Inconclusive);
        assert_eq!(classify_exit_code(&rows), ExitStatus::Config);

        std::fs::write(root.path().join("pom.xml"), "<project><modelVersion>")
            .expect("write pom.xml");
        let rows = probe_project(root.path(), "raeva.toml", &configured).await;
        let checks: Vec<&str> = rows.iter().map(|row| row.check.as_str()).collect();
        assert_eq!(checks, ["local", "central", "project repositories"]);
        assert_eq!(rows[2].outcome, Outcome::Config);
        assert!(
            rows[2].details.contains("pom.xml could not be read"),
            "{}",
            rows[2].details
        );
        server.stop();
    }

    /// Repositories are probed at once: the first answers only once the
    /// second has been asked, so one probe after the other would fail it.
    #[tokio::test]
    async fn repositories_are_probed_concurrently() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let asked = std::sync::Arc::new(AtomicBool::new(false));
        let seen = asked.clone();
        let slow = StubServer::start(move |_request| {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while !seen.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            let status = if seen.load(Ordering::SeqCst) {
                404
            } else {
                503
            };
            Response::new(status, "")
        });
        let flag = asked.clone();
        let other = StubServer::start(move |_request| {
            flag.store(true, Ordering::SeqCst);
            Response::new(404, "")
        });
        let root = tempfile::tempdir().expect("tempdir");
        let configured = format!(
            "[[repositories]]\nid = \"slow\"\nurl = \"http://{}/repo/\"\n\
             [[repositories]]\nid = \"central\"\nurl = \"http://{}/repo/\"\n",
            slow.addr(),
            other.addr()
        );
        let rows = probe_project(root.path(), "raeva.toml", &configured).await;
        slow.stop();
        other.stop();
        let checks: Vec<&str> = rows.iter().map(|row| row.check.as_str()).collect();
        assert_eq!(checks[..2], ["slow", "central"]);
        for row in &rows[..2] {
            assert_eq!(row.outcome, Outcome::Inconclusive, "{}", row.details);
        }
    }

    /// A default is left out only when every `[lock] jdks` target replaces
    /// it: a profile active on one JDK replaces it there only.
    #[tokio::test]
    async fn a_default_replaced_on_one_jdk_is_still_probed() {
        let root = tempfile::tempdir().expect("tempdir");
        let profile = format!(
            "<profiles><profile><id>jdk17</id><activation><jdk>17</jdk></activation>\
             <repositories>{}</repositories></profile></profiles></project>",
            pom_repository("central", "https://mirror.example.com/maven2/")
        );
        std::fs::write(
            root.path().join("pom.xml"),
            pom("app", "", "").replace("</project>", &profile),
        )
        .expect("write pom.xml");
        for (jdks, replaced) in [("[\"17\"]", true), ("[\"17\", \"21\"]", false)] {
            let config = config_in(
                root.path(),
                "raeva.toml",
                &format!("[lock]\njdks = {jdks}\n"),
            );
            let (client, _cache) = super::build_probe_client(&config)
                .await
                .expect("probe client");
            let (_, defaults) = super::project_repositories(&config, &client)
                .unwrap_or_else(|row| panic!("{}", row.details));
            assert_eq!(!defaults.is_empty(), replaced, "{jdks}: {defaults:?}");
        }
    }

    /// Doctor shows what sync would skip and never asks it: a plain HTTP
    /// repository and a default every module replaces. A `file:` repository
    /// whose directory is missing fails without being reported as reachable.
    #[tokio::test]
    async fn refused_replaced_and_missing_repositories_are_reported_as_sync_sees_them() {
        let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = hits.clone();
        let server = StubServer::start(move |_request| {
            seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Response::new(404, "")
        });
        let root = tempfile::tempdir().expect("tempdir");
        let repositories = [
            pom_repository("legacy", "http://repo.example.com/maven2/"),
            pom_repository("central", &format!("http://{}/central/", server.addr())),
        ]
        .concat();
        std::fs::write(
            root.path().join("pom.xml"),
            pom("app", &repositories, "<module>child</module>"),
        )
        .expect("write pom.xml");
        std::fs::create_dir(root.path().join("child")).expect("child");
        let child = pom("child", "", "").replace(
            "<modelVersion>4.0.0</modelVersion>",
            "<modelVersion>4.0.0</modelVersion><parent><groupId>com.example</groupId>\
             <artifactId>app</artifactId><version>1.0</version></parent>",
        );
        std::fs::write(root.path().join("child/pom.xml"), child).expect("write child");
        let missing = root.path().join("missing");
        let configured = format!(
            "[[repositories]]\nid = \"gone\"\nurl = \"{}\"\n",
            url::Url::from_directory_path(&missing).expect("file url")
        );
        let rows = probe_project(root.path(), "config.toml", "").await;
        assert!(
            !rows.iter().any(|row| row.check == "central"),
            "{:?}",
            rows.iter().map(|row| &row.check).collect::<Vec<_>>()
        );
        let legacy = rows
            .iter()
            .find(|row| row.check.starts_with("legacy"))
            .expect("legacy row");
        assert_eq!(legacy.outcome, Outcome::Inconclusive, "{}", legacy.details);
        assert!(legacy.details.contains("plain HTTP"), "{}", legacy.details);
        assert!(rows.iter().any(|row| row.check == "central (pom.xml)"));
        assert!(hits.load(std::sync::atomic::Ordering::SeqCst) > 0);
        server.stop();

        let rows = probe_project(root.path(), "raeva.toml", &configured).await;
        let gone = rows
            .iter()
            .find(|row| row.check == "gone")
            .expect("gone row");
        assert_eq!(gone.outcome, Outcome::Config, "{}", gone.details);
        assert!(
            gone.details.contains("is not a directory"),
            "{}",
            gone.details
        );
    }

    /// `Url::to_file_path` maps any `localhost` URL to its path, whatever the
    /// scheme, so a local Nexus must be asked, not checked as a directory.
    #[tokio::test]
    async fn a_localhost_http_repository_is_asked_not_read_as_a_directory() {
        let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = hits.clone();
        let server = StubServer::start(move |_request| {
            seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Response::new(404, "")
        });
        let root = tempfile::tempdir().expect("tempdir");
        std::fs::write(root.path().join("pom.xml"), pom("app", "", "")).expect("write pom.xml");
        let central = StubServer::start(|_| Response::new(404, ""));
        let configured = format!(
            "[[repositories]]\nid = \"nexus\"\nurl = \"http://localhost:{}/repository/maven-public/\"\n{}",
            server.addr().port(),
            local_central(&central),
        );
        let rows = probe_project(root.path(), "raeva.toml", &configured).await;
        server.stop();
        let nexus = rows
            .iter()
            .find(|row| row.check == "nexus")
            .expect("nexus row");
        assert_ne!(nexus.outcome, Outcome::Config, "{}", nexus.details);
        assert!(
            !nexus.details.contains("is not a directory"),
            "{}",
            nexus.details
        );
        assert!(
            hits.load(std::sync::atomic::Ordering::SeqCst) > 0,
            "{}",
            nexus.details
        );
    }

    #[test]
    fn a_store_that_cannot_be_written_fails() {
        let root = tempfile::tempdir().expect("tempdir");
        let row = super::store_row(&root.path().join("raeva").join("store"));
        assert_eq!(row.outcome, Outcome::Info, "{}", row.details);
        let file = root.path().join("file");
        std::fs::write(&file, "").expect("write file");
        let row = super::store_row(&file.join("store"));
        assert_eq!(row.outcome, Outcome::Config, "{}", row.details);
    }

    fn repository(id: Option<&str>, url: &str) -> Repository {
        Repository::new(id.map(str::to_string), url, true, false)
    }

    #[test]
    fn credential_source_prefers_id_match_and_suppresses_default_cross_host() {
        let auth: Vec<AuthConfig> =
            toml::from_str::<std::collections::BTreeMap<String, Vec<AuthConfig>>>(
                "[[auth]]\nid = \"corp\"\ntoken = \"corp-token\"\n\n\
                 [[auth]]\ntoken = \"default-token\"\n\n[[auth]]\nid = \"empty\"\n",
            )
            .expect("parse auth")
            .remove("auth")
            .expect("auth entries");
        let url = "https://repo.example/maven2/";
        assert_eq!(
            credential_source(&auth, &repository(Some("corp"), url), true),
            Some(CredentialSource::ConfigId("corp".to_string()))
        );
        assert_eq!(
            credential_source(&auth, &repository(Some("other"), url), false),
            Some(CredentialSource::ConfigDefault)
        );
        assert_eq!(
            credential_source(&auth, &repository(Some("other"), url), true),
            None
        );
        // An entry without a usable credential never matches its id.
        assert_eq!(
            credential_source(&auth, &repository(Some("empty"), url), true),
            None
        );
        let local = repository(Some("corp"), "FILE:///srv/repo/");
        assert_eq!(credential_source(&auth, &local, false), None);
    }

    #[test]
    fn exit_code_follows_the_failure_classes() {
        use Outcome::*;
        for (outcomes, expected) in [
            (&[Ok, Inconclusive, Info][..], ExitStatus::Success),
            (&[Ok, Network], ExitStatus::Partial),
            (&[Auth, Config, Inconclusive], ExitStatus::Config),
            (&[Network, Network], ExitStatus::Network),
            (&[Network, Auth], ExitStatus::Failure),
            (&[Other], ExitStatus::Failure),
        ] {
            let rows: Vec<Row> = outcomes
                .iter()
                .map(|outcome| Row::new("check", "", *outcome))
                .collect();
            assert_eq!(classify_exit_code(&rows), expected, "{outcomes:?}");
        }
    }
}
