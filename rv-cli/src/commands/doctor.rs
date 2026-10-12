use std::collections::HashSet;
use std::path::Path;
use std::time::Duration;

use clap::Args;

use rv_config::{
    AuthConfig, Config, CredentialStore, KeyringCredentialStore, MirrorConfig, NormalizedEndpoint,
};
use rv_repo::{
    RepoClient, RepoError, Repository, build_unauthenticated_proxy, same_origin_redirect_policy,
};
use rv_version::Coord;

use crate::error::{CliError, ExitCodes, Result};
use crate::output::{Table, heading, is_json_mode, json_result, quiet_enabled};

/// Timeout for establishing TCP connections during the raw mirror
/// reachability probes.
const DOCTOR_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Total timeout for HTTP requests during diagnostics.
const DOCTOR_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Args)]
#[command(about = "Diagnose repository connectivity, TLS, and auth configuration")]
pub struct DoctorArgs {}

/// Diagnostic check rows. The table view is the structured output of this
/// command, so it goes to stdout; the heading is decorative chatter and goes
/// to stderr (and is suppressed under `--quiet`).
struct Row {
    check: String,
    status: &'static str,
    details: String,
    /// Outcome of this check, used to compute the overall exit code.
    outcome: Outcome,
}

/// Per-check classification used to drive the exit code mapping. The
/// distinction matters because callers want to react differently to auth
/// vs network vs structural failures: e.g. CI can retry on network errors
/// but should fail loud on misconfiguration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// The check ran cleanly.
    Ok,
    /// The check produced an inconclusive result (e.g. 404 for the probe
    /// artifact on a repository that does not host it). Does not count
    /// toward failure totals.
    Inconclusive,
    /// Trust/TLS/config errors: rv.toml, certificates, repository URLs.
    Config,
    /// Authentication-required (401/403).
    Auth,
    /// Network-level failure: timeout, DNS, connect, server 5xx.
    Network,
    /// Anything else worth surfacing (unexpected status codes, skipped
    /// checks due to upstream failures).
    Other,
}

pub async fn run(_args: &DoctorArgs, project_root: &Path) -> Result<()> {
    let config = Config::load(project_root)?;
    let mut rows: Vec<Row> = Vec::new();

    // Probe through a real `RepoClient` so each check exercises the exact
    // path a sync takes: mirror selection, credential resolution (including
    // cross-host default-credential suppression), proxy routing with
    // non_proxy_hosts, and the same-origin redirect policy. Probing the
    // configured URLs with a bare HTTP client false-failed behind corporate
    // mirrors (direct egress blocked) and never sent repository credentials,
    // so private repos always showed 401.
    match build_probe_client(&config).await {
        Ok((client, _cache_guard)) => {
            let raw_client = build_doctor_client(&config)?;
            probe_repositories(&config, &client, &raw_client, &mut rows).await;
        }
        Err(err) => {
            rows.push(Row {
                check: "repository client".to_string(),
                status: "[!]",
                details: format!(
                    "{err} (check proxy and credential configuration in rv.toml / settings.xml)"
                ),
                outcome: Outcome::Config,
            });
        }
    }

    let issues = rows
        .iter()
        .filter(|row| !matches!(row.outcome, Outcome::Ok | Outcome::Inconclusive))
        .count();
    let exit_code = classify_exit_code(&rows);

    if is_json_mode() {
        let checks: Vec<_> = rows
            .iter()
            .map(|row| {
                serde_json::json!({
                    "check": row.check,
                    "status": row.status,
                    "details": row.details,
                })
            })
            .collect();
        let mut data = serde_json::json!({
            "issues": issues,
            "checks": checks,
        });
        // On failure, carry the top-level `exit_code` and `error` fields so the
        // doctor envelope matches the shape the generic error envelope (and the
        // lock-verify failure envelope) produce. `json_result` hoists these out
        // of the data object to sit next to `success`. Without them, JSON
        // consumers had to special-case doctor failures.
        if issues > 0
            && let serde_json::Value::Object(map) = &mut data
        {
            map.insert("exit_code".to_string(), serde_json::json!(exit_code));
            map.insert(
                "error".to_string(),
                serde_json::json!(format!(
                    "{issues} repository check(s) failed; see checks for details"
                )),
            );
        }
        json_result(issues == 0, data);
        // The doctor envelope above already carries `success: false` and the
        // full structured payload, so signal failure through an
        // `AlreadyReported` sentinel: the top-level handler will exit with
        // the carried code without printing a second envelope.
        if issues > 0 {
            return Err(CliError::AlreadyReported { exit_code });
        }
        return Ok(());
    }

    if !quiet_enabled() {
        eprintln!("{}", heading("doctor results"));
    }
    let mut table = Table::new(["Check", "Status", "Details"]);
    for row in &rows {
        table.add_row([row.check.as_str(), row.status, row.details.as_str()]);
    }
    println!("{}", table.render());

    if issues > 0 {
        // Use `AlreadyReported` so the table on stdout is the sole report
        // and we can still emit a specialized exit code (config/network/
        // partial) rather than the generic `Message` mapping.
        return Err(CliError::AlreadyReported { exit_code });
    }

    Ok(())
}

/// Build the `RepoClient` used for doctor probes.
///
/// The metadata cache is pointed at a throwaway directory so every probe
/// exercises the live network path instead of being satisfied by a cache
/// entry from a previous sync, and the network settings are tightened to a
/// single attempt with a bounded timeout so a dead endpoint reports quickly.
/// The returned `TempDir` guard must outlive the client.
async fn build_probe_client(config: &Config) -> Result<(RepoClient, tempfile::TempDir)> {
    let cache_dir = tempfile::tempdir()
        .map_err(|err| CliError::Message(format!("failed to create doctor probe cache: {err}")))?;
    let mut probe_config = config.clone();
    probe_config.paths.store_dir = cache_dir.path().join("store");
    probe_config.network.timeout = DOCTOR_REQUEST_TIMEOUT.as_secs();
    probe_config.network.retries = 0;
    let client = RepoClient::new(&probe_config)
        .await?
        .with_allow_missing_checksums(true);
    Ok((client, cache_dir))
}

/// Probe every configured repository and append a row per check.
///
/// Each repository is probed through `client.fetch_metadata` against the
/// origin repo, so the client applies the same mirror substitution and
/// credential policy as a real sync. When a mirror substitutes the URL, the
/// row is labeled with the mirror id and an additional unauthenticated
/// reachability check of the mirror endpoint itself is added: the client's
/// internal mirror-down fallback to the origin can mask a dead mirror in the
/// main probe, and the extra row keeps it visible.
async fn probe_repositories(
    config: &Config,
    client: &RepoClient,
    raw_client: &reqwest::Client,
    rows: &mut Vec<Row>,
) {
    let mut probed_mirrors: HashSet<String> = HashSet::new();

    for repo in config.repositories() {
        let origin = Repository::from(repo);
        let base_label = origin
            .id
            .clone()
            .unwrap_or_else(|| "repository".to_string());
        let resolution = resolve_mirror(config.mirrors(), &origin);
        let label = match &resolution.mirror_label {
            Some(mirror) => format!("{base_label} (via mirror {mirror})"),
            None => base_label.clone(),
        };

        // Validate the effective URL up front so a malformed entry reports
        // as a config error rather than an opaque fetch failure.
        if let Err(err) = resolution.repository.base_url() {
            rows.push(Row {
                check: label,
                status: "[!]",
                details: format!("{err} (check repository URL in rv.toml)"),
                outcome: Outcome::Config,
            });
            continue;
        }

        let Some(coord) = probe_coord(&origin) else {
            rows.push(Row {
                check: label,
                status: "[!]",
                details: "repository has both releases and snapshots disabled".to_string(),
                outcome: Outcome::Config,
            });
            continue;
        };

        let row = match client.fetch_metadata(&origin, &coord).await {
            Ok(_) => Row {
                check: label,
                status: "[OK]",
                details: "metadata probe succeeded".to_string(),
                outcome: Outcome::Ok,
            },
            Err(err) => {
                // Resolve which credential the probe attached (by source only,
                // never the secret values) so the 401 hint can distinguish "no
                // credentials configured" from "credentials rejected", and can
                // name the store they actually came from. Only on failure: a
                // passing row needs no hint, and this reads the OS credential
                // store.
                let credential = credential_source(
                    config.auth(),
                    &KeyringCredentialStore,
                    &resolution.repository,
                    resolution.host_changed,
                );
                let (status, details, outcome) = classify_probe_error(err, credential.as_ref());
                Row {
                    check: label,
                    status,
                    details,
                    outcome,
                }
            }
        };
        rows.push(row);

        // Supplementary mirror reachability check (deduped across repos that
        // share a mirror). Unauthenticated by design: it only answers "is
        // the mirror endpoint alive", so no credential can leak to a
        // possibly cross-host mirror.
        if let Some(mirror_label) = &resolution.mirror_label
            && probed_mirrors.insert(resolution.repository.url.clone())
        {
            rows.push(
                mirror_reachability_row(
                    raw_client,
                    format!("mirror {mirror_label}"),
                    &resolution.repository,
                )
                .await,
            );
        }
    }
}

/// Outcome of resolving a repository through the configured mirrors for
/// labeling and the supplementary reachability probe.
struct MirrorResolution {
    /// Repository after substitution; identical to the origin when no
    /// mirror matched.
    repository: Repository,
    /// `Some(display label)` when a mirror substituted the URL.
    mirror_label: Option<String>,
    /// True when the substitution crossed origins (sync suppresses default
    /// credentials in that case).
    host_changed: bool,
}

fn resolve_mirror(mirrors: &[MirrorConfig], repo: &Repository) -> MirrorResolution {
    let (repository, mirror, host_changed) = rv_repo::resolve_mirror(mirrors, repo);
    MirrorResolution {
        repository,
        mirror_label: mirror.map(|m| m.id.clone().unwrap_or_else(|| "<unnamed>".to_string())),
        host_changed,
    }
}

/// Where the credential the probe attached came from. Source only: secret
/// values are never read.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CredentialSource {
    /// An OS credential-store entry for the resolved endpoint. These win over
    /// every configured entry and silently shadow them, so a stale one has to
    /// be named explicitly.
    Keyring(String),
    /// A configured entry scoped to the resolved repository id.
    ConfigId(String),
    /// The default (id-less) configured entry.
    ConfigDefault,
}

impl CredentialSource {
    /// Subject of the "… were sent but rejected" sentence.
    fn label(&self) -> String {
        match self {
            Self::Keyring(endpoint) => {
                format!("the OS credential store entry for {endpoint}")
            }
            Self::ConfigId(id) => format!("credentials for id '{id}'"),
            Self::ConfigDefault => "default credentials".to_string(),
        }
    }
}

/// Identify which credential (if any) the sync path would attach to the
/// resolved repository, by source only; secret values are never read. Mirrors
/// rv-repo's crate-internal `AuthStore` lookup, in its precedence order: an OS
/// credential-store entry for the resolved endpoint wins over everything
/// (including across a cross-host mirror substitution, since the entry is
/// keyed by that endpoint); then an id-scoped config entry matching the
/// resolved repo id; then the default (id-less) entry, unless the mirror
/// substitution crossed hosts, in which case sync suppresses it.
///
/// Store errors (including an unavailable backend) count as "no entry", the
/// same fallback `AuthStore` takes.
fn credential_source(
    auth: &[AuthConfig],
    store: &dyn CredentialStore,
    resolved: &Repository,
    host_changed: bool,
) -> Option<CredentialSource> {
    if let Ok(endpoint) = NormalizedEndpoint::parse(&resolved.url)
        && matches!(store.get(&endpoint), Ok(Some(_)))
    {
        return Some(CredentialSource::Keyring(endpoint.as_str().to_string()));
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
    if host_changed {
        return None;
    }
    auth.iter()
        .filter(usable)
        .find(|entry| entry.id.is_none())
        .map(|_| CredentialSource::ConfigDefault)
}

/// Build the probe coordinate for a repository.
///
/// Well-known repositories get a coordinate whose `maven-metadata.xml` is
/// known to exist (Google's Android Maven CDN 404s on most generic paths),
/// everything else probes `org.apache:maven` (the path Maven Central has
/// served for its whole lifetime). On a private repository the generic
/// probe usually 404s, which is reported as inconclusive; connectivity,
/// TLS, proxy, and auth problems (401/403) still surface accurately.
/// Returns `None` when the repository disables both releases and snapshots.
fn probe_coord(repo: &Repository) -> Option<Coord> {
    let (group, artifact) = probe_group_artifact(repo.id.as_deref(), &repo.url);
    let version = if repo.releases_enabled {
        "1.0"
    } else if repo.snapshots_enabled {
        "1.0-SNAPSHOT"
    } else {
        return None;
    };
    Coord::parse(&format!("{group}:{artifact}:{version}")).ok()
}

fn probe_group_artifact(id: Option<&str>, base_url: &str) -> (&'static str, &'static str) {
    let id_matches_google = matches!(id, Some("google"));
    let host_matches_google = base_url.contains("dl.google.com");
    if id_matches_google || host_matches_google {
        ("androidx.core", "core")
    } else {
        ("org.apache", "maven")
    }
}

/// Map a failed probe to a row status, human details, and outcome class.
///
/// `credential` names the credential source the sync path would have
/// attached (source only, never the secret) so the 401/403 hint can
/// distinguish "nothing was sent, configure credentials" from "credentials
/// were sent and rejected", and can point at the store that actually supplied
/// them.
fn classify_probe_error(
    err: RepoError,
    credential: Option<&CredentialSource>,
) -> (&'static str, String, Outcome) {
    if let Some(code) = err.status_code() {
        if code == 401 || code == 403 {
            let details = match credential {
                // A stored entry outranks rv.toml and settings.xml, so
                // editing those files cannot fix a rejected one.
                Some(source @ CredentialSource::Keyring(endpoint)) => format!(
                    "{code} ({} was sent but rejected; run 'rv login {endpoint}' to replace \
                     it — a stored entry shadows any credentials in rv.toml or \
                     ~/.m2/settings.xml)",
                    source.label()
                ),
                Some(source) => format!(
                    "{code} ({} were sent but rejected; check the username/password \
                     or token in ~/.m2/settings.xml or rv.toml)",
                    source.label()
                ),
                None => format!(
                    "{code} (no credentials were sent; configure credentials in \
                     ~/.m2/settings.xml or rv.toml)"
                ),
            };
            return ("[!]", details, Outcome::Auth);
        }
        if code == 407 {
            return (
                "[!]",
                format!("{code} (proxy authentication required; check proxy credentials)"),
                Outcome::Auth,
            );
        }
        if code == 404 {
            return (
                "[?]",
                "404 for the probe artifact (repository reachable; many repositories do not \
                 host the probe path, try resolving a known artifact)"
                    .to_string(),
                Outcome::Inconclusive,
            );
        }
        if (500..600).contains(&code) {
            return (
                "[!]",
                format!("{code} (repository server error, try again later)"),
                Outcome::Network,
            );
        }
        return ("[!]", err.to_string(), Outcome::Other);
    }

    match err {
        RepoError::Http(http_err) => ("[!]", format_connection_error(http_err), Outcome::Network),
        RepoError::InvalidMetadata(_) => (
            "[?]",
            format!(
                "{err} (the response at the probe path was not Maven metadata; a proxy or \
                 captive portal may be interfering)"
            ),
            Outcome::Inconclusive,
        ),
        RepoError::ChecksumMismatch { .. } => (
            "[!]",
            format!("{err} (possible tampering or proxy interference)"),
            Outcome::Other,
        ),
        RepoError::SnapshotsDisabled { .. } | RepoError::InvalidCoord(_) | RepoError::Url(_) => (
            "[!]",
            format!("{err} (check repository configuration in rv.toml)"),
            Outcome::Config,
        ),
        RepoError::AuthError(_) => (
            "[!]",
            format!("{err} (check credential configuration)"),
            Outcome::Config,
        ),
        other => ("[!]", other.to_string(), Outcome::Other),
    }
}

/// Unauthenticated reachability check of a mirror endpoint.
///
/// The main probe goes through `RepoClient`, which falls back to the origin
/// when the mirror is broken (Maven parity), so a dead mirror could hide
/// behind a passing main row. This check GETs the mirror base URL directly:
/// any HTTP response, including 401/403/404, proves the endpoint is alive;
/// 5xx and connection-level failures fail the row. No credentials are ever
/// attached, so nothing can leak to a cross-host mirror.
async fn mirror_reachability_row(
    client: &reqwest::Client,
    label: String,
    mirror: &Repository,
) -> Row {
    let (probe_url, display_url) = match mirror_probe_urls(mirror) {
        Ok(pair) => pair,
        Err(err) => {
            return Row {
                check: label,
                status: "[!]",
                details: format!("{err} (check mirror URL configuration)"),
                outcome: Outcome::Config,
            };
        }
    };
    match client.get(probe_url).send().await {
        Ok(response) if response.status().is_server_error() => Row {
            check: label,
            status: "[!]",
            details: format!(
                "{} at {display_url} (mirror server error, try again later)",
                response.status()
            ),
            outcome: Outcome::Network,
        },
        Ok(response) => Row {
            check: label,
            status: "[OK]",
            details: format!(
                "{} at {display_url} (mirror endpoint reachable)",
                response.status()
            ),
            outcome: Outcome::Ok,
        },
        Err(err) => Row {
            check: label,
            status: "[!]",
            details: format!("{} ({display_url})", format_connection_error(err)),
            outcome: Outcome::Network,
        },
    }
}

/// Build the (probe, display) URL pair for a mirror reachability check.
/// Userinfo is stripped from both so credentials embedded in a configured
/// URL are never sent by this unauthenticated probe nor rendered in the
/// doctor table; the display URL additionally drops the query string so
/// query-embedded secrets cannot leak either.
fn mirror_probe_urls(mirror: &Repository) -> std::result::Result<(url::Url, String), RepoError> {
    let mut probe = mirror.base_url()?;
    let _ = probe.set_username("");
    let _ = probe.set_password(None);
    let mut display = probe.clone();
    display.set_query(None);
    Ok((probe, display.to_string()))
}

/// Build the raw HTTP client used for the unauthenticated mirror
/// reachability probes.
///
/// Applies proxy settings from `rv.toml` / `settings.xml` through the same
/// `ProxyConfig` entries that `RepoClient::new` reads, including
/// `non_proxy_hosts` routing, so the probe reflects the same proxy path a
/// sync would take. Proxy credentials are not attached: the probe's goal is
/// reachability through the proxy, and a 407 surfaces as a failure naming it.
fn build_doctor_client(config: &Config) -> Result<reqwest::Client> {
    // Match the sync client's proxy policy: only proxies from Maven/rv
    // configuration apply, never HTTP(S)_PROXY environment variables, so the
    // probe diagnoses the same network path sync will use.
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .redirect(same_origin_redirect_policy())
        .connect_timeout(DOCTOR_CONNECT_TIMEOUT)
        .timeout(DOCTOR_REQUEST_TIMEOUT);

    for proxy_config in config.proxies() {
        if let Ok(proxy) = build_unauthenticated_proxy(proxy_config) {
            builder = builder.proxy(proxy);
        }
    }

    Ok(builder.build()?)
}

/// Map per-check outcomes to a single exit code.
///
/// Rules (in priority order):
/// - No failing checks: exit 0 (caller handles).
/// - Some checks passed alongside failures: `PARTIAL_SUCCESS`. Operators
///   can tell that the binary did real work even though something needs
///   attention.
/// - All checks failed and every failure is auth-class: `CONFIG_ERROR`.
///   Surfacing auth as config nudges users to fix credentials (rv.toml /
///   settings.xml) rather than blaming the network.
/// - All checks failed and every failure is network-class: `NETWORK_ERROR`.
///   CI tooling typically retries this class of error.
/// - Anything else (mixed failure classes, structural errors, etc.):
///   `GENERAL_ERROR`.
fn classify_exit_code(rows: &[Row]) -> i32 {
    let mut total = 0usize;
    let mut passed = 0usize;
    let mut failed = 0usize;
    let mut auth_failures = 0usize;
    let mut network_failures = 0usize;
    let mut config_failures = 0usize;

    for row in rows {
        match row.outcome {
            Outcome::Ok => {
                total += 1;
                passed += 1;
            }
            // Inconclusive checks (e.g. 404 at the probe path) count as
            // neither pass nor fail: they don't influence exit code mapping.
            Outcome::Inconclusive => {}
            Outcome::Auth => {
                total += 1;
                failed += 1;
                auth_failures += 1;
            }
            Outcome::Network => {
                total += 1;
                failed += 1;
                network_failures += 1;
            }
            Outcome::Config => {
                total += 1;
                failed += 1;
                config_failures += 1;
            }
            Outcome::Other => {
                total += 1;
                failed += 1;
            }
        }
    }

    if failed == 0 {
        return 0;
    }
    // `total - passed - failed` would be inconclusive entries, which we
    // already exclude. If at least one real check passed and at least one
    // failed, signal partial success regardless of failure class.
    if passed > 0 && failed > 0 {
        return ExitCodes::PARTIAL_SUCCESS;
    }
    debug_assert_eq!(total, failed);
    // Promote a pure auth-only or pure config/auth/TLS failure set to
    // CONFIG_ERROR. Both classes share the same remediation surface
    // (credentials in rv.toml/settings.xml, OS trust store / CA certs) and CI
    // tooling treats config errors as non-retryable distinctly from network.
    if failed == auth_failures + config_failures {
        return ExitCodes::CONFIG_ERROR;
    }
    if failed == network_failures {
        return ExitCodes::NETWORK_ERROR;
    }
    ExitCodes::GENERAL_ERROR
}

fn format_connection_error(err: reqwest::Error) -> String {
    // `reqwest::Error::Display` may include the request URL which can
    // contain `user:pass@host` userinfo. Strip the URL before formatting
    // so credentials never leak into the doctor table.
    let safe = err.without_url();
    if safe.is_timeout() {
        return format!(
            "{} (connection or response too slow; check network latency)",
            safe
        );
    }
    // TLS handshake failures (e.g. rustls `InvalidCertificate`, unknown CA)
    // surface as `is_connect()` errors because the failure occurs during
    // connection establishment, before any HTTP bytes are exchanged. Check
    // for TLS/certificate keywords in both the `is_connect()` and
    // `is_request()` branches so the cert-specific hint fires regardless of
    // which phase reqwest classifies the error into.
    let err_str = safe.to_string().to_lowercase();
    let is_tls = err_str.contains("certificate")
        || err_str.contains("tls")
        || err_str.contains("ssl")
        || err_str.contains("handshake")
        || err_str.contains("trust");
    if is_tls {
        return format!(
            "{} (certificate validation failed; install the CA into your OS trust store)",
            safe
        );
    }
    if safe.is_connect() {
        return format!(
            "{} (cannot establish connection; verify URL, network, and firewall)",
            safe
        );
    }
    if safe.is_request() {
        // Catch any remaining request-phase errors that mention TLS but
        // weren't caught by the keyword check above (defensive).
        return format!(
            "{} (request failed; check proxy and firewall settings)",
            safe
        );
    }
    safe.to_string()
}

#[cfg(test)]
mod tests {
    use super::{
        CredentialSource, Outcome, Row, classify_exit_code, classify_probe_error,
        credential_source, probe_coord, probe_group_artifact, resolve_mirror,
    };
    use crate::error::ExitCodes;
    use rv_config::{
        AuthConfig, CredentialError, CredentialRecord, CredentialStore, MirrorConfig,
        NormalizedEndpoint,
    };
    use rv_repo::{RepoError, Repository};

    fn mirror_config(id: Option<&str>, url: &str, mirror_of: &[&str]) -> MirrorConfig {
        MirrorConfig {
            id: id.map(str::to_string),
            url: url.to_string(),
            mirror_of: mirror_of.iter().map(|value| value.to_string()).collect(),
        }
    }

    fn central() -> Repository {
        Repository::new(
            Some("central".to_string()),
            "https://repo1.maven.org/maven2/",
            true,
            false,
        )
    }

    // --- mirror resolution ---

    #[test]
    fn resolve_mirror_matches_by_id_and_labels() {
        let mirrors = vec![mirror_config(
            Some("corp"),
            "https://mirror.example/",
            &["central"],
        )];
        let resolution = resolve_mirror(&mirrors, &central());
        assert_eq!(resolution.repository.url, "https://mirror.example/");
        assert_eq!(resolution.mirror_label.as_deref(), Some("corp"));
        assert!(resolution.host_changed);
        assert_eq!(resolution.repository.id.as_deref(), Some("corp"));
    }

    #[test]
    fn resolve_mirror_exact_id_wins_over_earlier_wildcard() {
        let mirrors = vec![
            mirror_config(Some("any"), "https://wildcard.example/", &["*"]),
            mirror_config(Some("corp"), "https://corp.example/", &["central"]),
        ];
        let resolution = resolve_mirror(&mirrors, &central());
        assert_eq!(resolution.repository.url, "https://corp.example/");
    }

    #[test]
    fn resolve_mirror_respects_exclusions() {
        let mirrors = vec![mirror_config(
            Some("corp"),
            "https://mirror.example/",
            &["*", "!central"],
        )];
        let resolution = resolve_mirror(&mirrors, &central());
        assert_eq!(resolution.repository.url, central().url);
        assert!(resolution.mirror_label.is_none());
    }

    #[test]
    fn resolve_mirror_ignores_self_referential_mirror() {
        let url = "https://repo1.maven.org/maven2/";
        let mirrors = vec![mirror_config(Some("central"), url, &["central"])];
        let resolution = resolve_mirror(&mirrors, &central());
        assert_eq!(resolution.repository.url, url);
        assert!(resolution.mirror_label.is_none());
        assert!(!resolution.host_changed);
    }

    #[test]
    fn resolve_mirror_cross_host_unnamed_mirror_drops_origin_id() {
        let mirrors = vec![mirror_config(None, "https://cdn.example/", &["*"])];
        let resolution = resolve_mirror(&mirrors, &central());
        assert!(resolution.host_changed);
        assert_eq!(resolution.repository.id, None);
        assert_eq!(resolution.mirror_label.as_deref(), Some("<unnamed>"));
    }

    #[test]
    fn resolve_mirror_same_host_unnamed_mirror_inherits_origin_id() {
        let mirrors = vec![mirror_config(None, "https://nexus.corp/mirror/", &["*"])];
        let repo = Repository::new(
            Some("internal".to_string()),
            "https://nexus.corp/repo/",
            true,
            false,
        );
        let resolution = resolve_mirror(&mirrors, &repo);
        assert!(!resolution.host_changed);
        assert_eq!(resolution.repository.id.as_deref(), Some("internal"));
    }

    #[test]
    fn resolve_mirror_scheme_and_port_changes_suppress_origin_credentials() {
        let repo = repository(Some("corp"), "https://nexus.corp/repo/");
        for url in [
            "http://nexus.corp/mirror/",
            "http://nexus.corp:443/mirror/",
            "https://nexus.corp:8443/mirror/",
        ] {
            for id in [None, Some("mirror"), Some("corp")] {
                let mirrors = vec![mirror_config(id, url, &["*"])];
                let resolution = resolve_mirror(&mirrors, &repo);
                assert!(resolution.host_changed, "{url}");
                assert_eq!(resolution.repository.id.as_deref(), id);
                assert_eq!(
                    resolution.mirror_label.as_deref(),
                    Some(id.unwrap_or("<unnamed>"))
                );
                assert_eq!(
                    credential_source(
                        &auth_entries(),
                        &FakeCredentialStore::empty(),
                        &resolution.repository,
                        resolution.host_changed,
                    ),
                    id.filter(|id| *id == "corp")
                        .map(|id| CredentialSource::ConfigId(id.to_string())),
                    "{url} with mirror id {id:?}",
                );
            }
        }
    }

    #[test]
    fn resolve_mirror_default_port_keeps_origin_credentials() {
        let mirrors = vec![mirror_config(
            None,
            "https://nexus.corp:443/mirror/",
            &["*"],
        )];
        let repo = repository(Some("corp"), "https://nexus.corp/repo/");
        let resolution = resolve_mirror(&mirrors, &repo);
        assert!(!resolution.host_changed);
        assert_eq!(resolution.repository.id, repo.id);
        assert_eq!(
            credential_source(
                &auth_entries(),
                &FakeCredentialStore::empty(),
                &resolution.repository,
                resolution.host_changed,
            ),
            Some(CredentialSource::ConfigId("corp".to_string())),
        );
    }

    #[test]
    fn resolve_mirror_multi_id_pattern_matches_either() {
        let mirrors = vec![mirror_config(
            Some("multi"),
            "https://multi.example/",
            &["central,snapshots"],
        )];
        assert_eq!(
            resolve_mirror(&mirrors, &central()).repository.url,
            "https://multi.example/"
        );
        let other = Repository::new(
            Some("releases".to_string()),
            "https://releases.example/",
            true,
            false,
        );
        assert_eq!(
            resolve_mirror(&mirrors, &other).repository.url,
            other.url,
            "a repo not in the include list is left alone"
        );
    }

    #[test]
    fn resolve_mirror_external_pattern_skips_internal_repos() {
        let mirrors = vec![mirror_config(
            Some("ext"),
            "https://mirror.example/",
            &["external:*"],
        )];
        let internal = Repository::new(
            Some("local".to_string()),
            "http://localhost:8081/repo/",
            true,
            false,
        );
        assert!(resolve_mirror(&mirrors, &internal).mirror_label.is_none());
        assert!(resolve_mirror(&mirrors, &central()).mirror_label.is_some());
    }

    fn proxy_test_config(root: &std::path::Path, contents: &str) -> rv_config::Config {
        std::fs::write(root.join("rv.toml"), contents).expect("write config");
        temp_env::with_vars(
            [
                ("HOME", Some(root)),
                ("USERPROFILE", Some(root)),
                ("RAEVA_HOME", Some(root)),
            ],
            || {
                let mut config = rv_config::Config::load(root)
                    .expect("config")
                    .without_os_credentials();
                config.ensure_maven_settings_loaded();
                config.network.timeout = 5;
                config.network.retries = 0;
                config
            },
        )
    }

    fn spawn_probe_server(
        proxied: bool,
        requests: tokio::sync::mpsc::UnboundedSender<(bool, String)>,
    ) -> (std::net::SocketAddr, rv_test_support::http::StubServer) {
        use rv_test_support::http::{Response, StubServer};
        use sha2::{Digest, Sha256};

        let server = StubServer::start(move |request| {
            let metadata = "<metadata><groupId>org.apache.maven</groupId><artifactId>maven</artifactId></metadata>";
            let body = if request.path.ends_with(".sha256") {
                format!("{:x}", Sha256::digest(metadata.as_bytes()))
            } else {
                metadata.to_string()
            };
            requests
                .send((proxied, request.raw.clone()))
                .expect("record request");
            Response::new(200, body)
        });
        (server.addr(), server)
    }

    #[tokio::test]
    async fn doctor_proxy_bypass_matches_sync_client() {
        let (send, mut requests) = tokio::sync::mpsc::unbounded_channel();
        let (origin, origin_task) = spawn_probe_server(false, send.clone());
        let (proxy, proxy_task) = spawn_probe_server(true, send);
        for (host, protocol, bypass, proxied) in [
            ("127.0.0.1", None, "", true),
            ("127.0.0.1", Some("http"), "127.0.0.1", false),
            ("127.0.0.1", Some("HTTP"), "127.0.0.1.", false),
            ("localhost", Some("http"), "  LOCALHOST.  ", false),
            ("localhost", Some("http"), "*.localhost", false),
            ("localhost", Some("http"), ".LOCALHOST.", false),
            ("127.0.0.1", Some("http"), "  *  ", false),
            ("127.0.0.1", Some("all"), "*", false),
            ("127.0.0.1", Some("http"), "other.example", true),
            ("127.0.0.1", Some("http"), "*.other.example", true),
            ("127.0.0.1", Some("https"), "other.example", false),
        ] {
            let root = tempfile::tempdir().expect("tempdir");
            let url = format!("http://{host}:{}/", origin.port());
            let protocol = protocol
                .map(|p| format!("protocol = {p:?}"))
                .unwrap_or_default();
            let bypass_list: Vec<_> = if bypass.is_empty() {
                Vec::new()
            } else {
                vec![bypass]
            };
            let config = proxy_test_config(
                root.path(),
                &format!(
                    r#"
[[repositories]]
id = "probe"
url = "{url}"
[[proxies]]
{protocol}
host = "127.0.0.1"
port = {proxy_port}
username = "proxy-user"
password = "proxy-password"
non_proxy_hosts = {bypass_list:?}
"#,
                    proxy_port = proxy.port(),
                ),
            );
            let raw = super::build_doctor_client(&config).expect("doctor client");
            let sync = rv_repo::RepoClient::new(&config)
                .await
                .expect("sync client");
            let repo = Repository::from(&config.repositories()[0]);
            assert_eq!(
                raw.get(&url).send().await.expect("doctor request").status(),
                200
            );
            let (used_proxy, request) = requests.try_recv().expect("doctor request recorded");
            assert_eq!(
                used_proxy, proxied,
                "doctor: {host}, {protocol}, {bypass:?}"
            );
            assert!(!request.to_ascii_lowercase().contains("authorization:"));
            assert!(requests.try_recv().is_err());

            sync.fetch_metadata(&repo, &probe_coord(&repo).expect("coord"))
                .await
                .expect("sync metadata and checksum");
            let mut sync_requests = Vec::new();
            while let Ok(request) = requests.try_recv() {
                sync_requests.push(request);
            }
            assert!(!sync_requests.is_empty(), "sync must reach the server");
            for (used_proxy, request) in sync_requests {
                assert_eq!(
                    used_proxy, proxied,
                    "sync: {host}, {protocol}, {bypass:?}, {request}"
                );
                let authenticated = request
                    .to_ascii_lowercase()
                    .contains("proxy-authorization:");
                assert_eq!(authenticated, proxied, "{request}");
                assert!(!request.to_ascii_lowercase().contains("\r\nauthorization:"));
            }
        }
        origin_task.stop();
        proxy_task.stop();
    }

    #[tokio::test]
    async fn doctor_skips_invalid_proxy_entries_and_ignores_proxy_credentials() {
        let (send, mut requests) = tokio::sync::mpsc::unbounded_channel();
        let (proxy, task) = spawn_probe_server(true, send);
        let root = tempfile::tempdir().expect("tempdir");
        let config = proxy_test_config(
            root.path(),
            &format!(
                r#"
[[proxies]]
host = "user@invalid.example"
port = 8080
[[proxies]]
host = "127.0.0.1"
port = {}
auth_type = "bearer"
"#,
                proxy.port()
            ),
        );
        let client = super::build_doctor_client(&config)
            .expect("invalid entry skipped, missing token ignored");
        assert_eq!(
            client
                .get("http://repo.invalid/")
                .send()
                .await
                .expect("proxy request")
                .status(),
            200
        );
        let (proxied, request) = requests.try_recv().expect("request recorded");
        assert!(proxied);
        assert!(!request.to_ascii_lowercase().contains("authorization:"));
        task.stop();
    }

    // --- credential source replication ---

    /// Stand-in for the OS credential store: holds records for exact
    /// normalized endpoints, or reports the backend as unavailable.
    struct FakeCredentialStore {
        endpoints: Vec<String>,
        unavailable: bool,
    }

    impl FakeCredentialStore {
        fn empty() -> Self {
            Self {
                endpoints: Vec::new(),
                unavailable: false,
            }
        }

        fn with_entry(endpoint: &str) -> Self {
            Self {
                endpoints: vec![endpoint.to_string()],
                unavailable: false,
            }
        }

        fn unavailable() -> Self {
            Self {
                endpoints: Vec::new(),
                unavailable: true,
            }
        }
    }

    impl CredentialStore for FakeCredentialStore {
        fn get(
            &self,
            endpoint: &NormalizedEndpoint,
        ) -> std::result::Result<Option<CredentialRecord>, CredentialError> {
            if self.unavailable {
                return Err(CredentialError::BackendUnavailable("test".to_string()));
            }
            if self
                .endpoints
                .iter()
                .any(|stored| stored == endpoint.as_str())
            {
                return Ok(Some(CredentialRecord::bearer("stored-token")?));
            }
            Ok(None)
        }

        fn set(
            &self,
            _endpoint: &NormalizedEndpoint,
            _record: &CredentialRecord,
        ) -> std::result::Result<(), CredentialError> {
            unreachable!("read-only test credential store")
        }

        fn delete(
            &self,
            _endpoint: &NormalizedEndpoint,
        ) -> std::result::Result<bool, CredentialError> {
            unreachable!("read-only test credential store")
        }
    }

    fn repository(id: Option<&str>, url: &str) -> Repository {
        Repository::new(id.map(str::to_string), url, true, false)
    }

    /// A keyring record for the probed endpoint outranks every configured
    /// entry, exactly as `AuthStore` resolves it. Reporting the config source
    /// here (or "no credentials") sent users to edit files that the stored
    /// entry shadows.
    #[test]
    fn credential_source_reports_the_credential_store_first() {
        let auth = auth_entries();
        let repo = repository(Some("corp"), "https://repo.example/maven2/");

        let source = credential_source(
            &auth,
            &FakeCredentialStore::with_entry("https://repo.example/maven2/"),
            &repo,
            false,
        )
        .expect("keyring entry");
        assert_eq!(
            source,
            CredentialSource::Keyring("https://repo.example/maven2/".to_string())
        );

        // Endpoint-keyed, so it applies even across a cross-host mirror
        // substitution, where the configured default would be suppressed.
        assert!(matches!(
            credential_source(
                &auth,
                &FakeCredentialStore::with_entry("https://repo.example/maven2/"),
                &repository(None, "https://repo.example/maven2/"),
                true,
            ),
            Some(CredentialSource::Keyring(_))
        ));

        // The misattribution case: a repo with no configured credentials at
        // all still had a keyring record attached by the probe.
        assert!(matches!(
            credential_source(
                &[],
                &FakeCredentialStore::with_entry("https://repo.example/maven2/"),
                &repo,
                false,
            ),
            Some(CredentialSource::Keyring(_))
        ));

        // An entry for a different endpoint must not be claimed.
        assert_eq!(
            credential_source(
                &auth,
                &FakeCredentialStore::with_entry("https://other.example/maven2/"),
                &repo,
                false,
            ),
            Some(CredentialSource::ConfigId("corp".to_string()))
        );
    }

    /// An unavailable backend (or an endpoint the store cannot key) is not a
    /// credential: `AuthStore` falls through to the configured entries, and so
    /// must the report.
    #[test]
    fn credential_source_falls_back_when_the_store_cannot_answer() {
        let auth = auth_entries();
        assert_eq!(
            credential_source(
                &auth,
                &FakeCredentialStore::unavailable(),
                &repository(Some("corp"), "https://repo.example/maven2/"),
                false,
            ),
            Some(CredentialSource::ConfigId("corp".to_string()))
        );
        // A non-http endpoint has no keyring key at all.
        assert_eq!(
            credential_source(
                &auth,
                &FakeCredentialStore::empty(),
                &repository(Some("corp"), "file:///srv/repo/"),
                false,
            ),
            Some(CredentialSource::ConfigId("corp".to_string()))
        );
    }

    /// Entries are built through toml deserialization since the secret
    /// fields cannot be constructed directly without the secrecy crate.
    fn auth_entries() -> Vec<AuthConfig> {
        toml::from_str::<std::collections::BTreeMap<String, Vec<AuthConfig>>>(
            r#"
[[auth]]
id = "corp"
token = "corp-token"

[[auth]]
token = "default-token"
"#,
        )
        .expect("parse auth")
        .remove("auth")
        .expect("auth entries")
    }

    #[test]
    fn credential_source_prefers_id_match_and_suppresses_default_cross_host() {
        let auth = auth_entries();
        let store = FakeCredentialStore::empty();
        let corp = repository(Some("corp"), "https://repo.example/maven2/");
        let other = repository(Some("other"), "https://repo.example/maven2/");
        let anonymous = repository(None, "https://repo.example/maven2/");

        // Id-scoped entry wins for the resolved id, regardless of host change.
        assert_eq!(
            credential_source(&auth, &store, &corp, true),
            Some(CredentialSource::ConfigId("corp".to_string()))
        );
        // No id match, same host: the default applies.
        assert_eq!(
            credential_source(&auth, &store, &other, false),
            Some(CredentialSource::ConfigDefault)
        );
        // No id match, cross-host: sync suppresses the default, so doctor
        // must report that nothing was sent.
        assert_eq!(credential_source(&auth, &store, &other, true), None);
        assert_eq!(credential_source(&auth, &store, &anonymous, true), None);
    }

    #[test]
    fn credential_source_ignores_unusable_entries() {
        // An entry with an id but no usable credentials never matches.
        let auth = vec![auth_entry_no_creds(Some("corp"))];
        assert_eq!(
            credential_source(
                &auth,
                &FakeCredentialStore::empty(),
                &repository(Some("corp"), "https://repo.example/maven2/"),
                false,
            ),
            None
        );
    }

    fn auth_entry_no_creds(id: Option<&str>) -> AuthConfig {
        AuthConfig {
            id: id.map(str::to_string),
            username: None,
            password: None,
            token: None,
        }
    }

    // --- probe coordinates ---

    #[test]
    fn google_probe_targets_androidx_metadata() {
        assert_eq!(
            probe_group_artifact(Some("google"), "https://dl.google.com/dl/android/maven2/"),
            ("androidx.core", "core")
        );
        assert_eq!(
            probe_group_artifact(None, "https://dl.google.com/dl/android/maven2/"),
            ("androidx.core", "core")
        );
    }

    #[test]
    fn central_and_unknown_probe_target_apache_metadata() {
        assert_eq!(
            probe_group_artifact(Some("central"), "https://repo1.maven.org/maven2/"),
            ("org.apache", "maven")
        );
        assert_eq!(
            probe_group_artifact(Some("private"), "https://corp.example/maven"),
            ("org.apache", "maven")
        );
    }

    #[test]
    fn probe_coord_picks_snapshot_version_for_snapshot_only_repos() {
        let releases = central();
        let coord = probe_coord(&releases).expect("coord");
        assert_eq!(coord.version.to_string(), "1.0");

        let snapshots_only = Repository::new(
            Some("snaps".to_string()),
            "https://snapshots.example/",
            false,
            true,
        );
        let coord = probe_coord(&snapshots_only).expect("coord");
        assert_eq!(coord.version.to_string(), "1.0-SNAPSHOT");

        let disabled = Repository::new(
            Some("off".to_string()),
            "https://off.example/",
            false,
            false,
        );
        assert!(probe_coord(&disabled).is_none());
    }

    // --- probe error classification ---

    #[test]
    fn unauthorized_hint_depends_on_whether_credentials_were_sent() {
        let err = RepoError::AuthError("401 Unauthorized for https://repo.example/".to_string());
        let (_, details, outcome) = classify_probe_error(err, None);
        assert_eq!(outcome, Outcome::Auth);
        assert!(
            details.contains("no credentials were sent") && details.contains("configure"),
            "no-creds 401 must suggest configuring credentials: {details}"
        );

        let err = RepoError::AuthError("401 Unauthorized for https://repo.example/".to_string());
        let (_, details, outcome) =
            classify_probe_error(err, Some(&CredentialSource::ConfigId("corp".to_string())));
        assert_eq!(outcome, Outcome::Auth);
        assert!(
            details.contains("sent but rejected") && details.contains("'corp'"),
            "creds-sent 401 must say they were rejected: {details}"
        );
        assert!(
            !details.contains("configure credentials in"),
            "creds-sent 401 must not suggest configuring missing credentials: {details}"
        );
    }

    /// A rejected keyring credential is not fixable by editing settings.xml or
    /// rv.toml: the stored entry shadows both. The hint has to name the store
    /// and send the user back through `rv login`.
    #[test]
    fn unauthorized_hint_points_at_the_credential_store_when_it_supplied_the_secret() {
        let err = RepoError::AuthError("401 Unauthorized for https://repo.example/".to_string());
        let (_, details, outcome) = classify_probe_error(
            err,
            Some(&CredentialSource::Keyring(
                "https://repo.example/".to_string(),
            )),
        );
        assert_eq!(outcome, Outcome::Auth);
        assert!(
            details.contains("OS credential store entry for https://repo.example/")
                && details.contains("sent but rejected"),
            "keyring 401 must name the store: {details}"
        );
        assert!(
            details.contains("rv login https://repo.example/"),
            "keyring 401 must point at rv login: {details}"
        );
        assert!(
            details.contains("shadows"),
            "keyring 401 must explain that config credentials are shadowed: {details}"
        );
        assert!(
            !details.contains("no credentials were sent"),
            "keyring credentials were sent: {details}"
        );
    }

    #[test]
    fn not_found_probe_is_inconclusive() {
        let err = RepoError::NotFound("org/apache/maven/maven-metadata.xml".to_string());
        let (status, _, outcome) = classify_probe_error(err, None);
        assert_eq!(status, "[?]");
        assert_eq!(outcome, Outcome::Inconclusive);
    }

    #[test]
    fn server_error_probe_is_network_class() {
        let err = RepoError::UnexpectedResponse(
            "503 Service Unavailable for https://repo.example/".to_string(),
        );
        let (_, details, outcome) = classify_probe_error(err, None);
        assert_eq!(outcome, Outcome::Network);
        assert!(details.contains("server error"), "got {details}");
    }

    #[test]
    fn checksum_mismatch_probe_counts_as_issue() {
        let err = RepoError::ChecksumMismatch {
            path: "p".to_string(),
            expected: "aa".to_string(),
            actual: "bb".to_string(),
        };
        let (_, details, outcome) = classify_probe_error(err, None);
        assert_eq!(outcome, Outcome::Other);
        assert!(details.contains("tampering"), "got {details}");
    }

    // --- exit code mapping ---

    fn row(outcome: Outcome) -> Row {
        Row {
            check: "test".to_string(),
            status: "[?]",
            details: String::new(),
            outcome,
        }
    }

    #[test]
    fn all_ok_returns_zero() {
        let rows = vec![row(Outcome::Ok), row(Outcome::Ok)];
        assert_eq!(classify_exit_code(&rows), 0);
    }

    #[test]
    fn inconclusive_only_returns_zero() {
        let rows = vec![row(Outcome::Inconclusive)];
        assert_eq!(classify_exit_code(&rows), 0);
    }

    #[test]
    fn mixed_pass_and_fail_returns_partial_success() {
        let rows = vec![row(Outcome::Ok), row(Outcome::Network)];
        assert_eq!(classify_exit_code(&rows), ExitCodes::PARTIAL_SUCCESS);
    }

    #[test]
    fn all_auth_failures_returns_config_error() {
        let rows = vec![row(Outcome::Auth), row(Outcome::Auth)];
        assert_eq!(classify_exit_code(&rows), ExitCodes::CONFIG_ERROR);
    }

    #[test]
    fn all_network_failures_returns_network_error() {
        let rows = vec![row(Outcome::Network), row(Outcome::Network)];
        assert_eq!(classify_exit_code(&rows), ExitCodes::NETWORK_ERROR);
    }

    #[test]
    fn mixed_failure_classes_returns_general_error() {
        // Auth + network with no passing check: neither class is exclusive,
        // so we fall back to the generic code.
        let rows = vec![row(Outcome::Auth), row(Outcome::Network)];
        assert_eq!(classify_exit_code(&rows), ExitCodes::GENERAL_ERROR);
    }

    #[test]
    fn all_config_failures_returns_config_error() {
        // Trust/TLS/config failures share a remediation surface with auth
        // failures and should map to CONFIG_ERROR so CI can distinguish
        // a misconfigured client from a flaky network.
        let rows = vec![row(Outcome::Config)];
        assert_eq!(classify_exit_code(&rows), ExitCodes::CONFIG_ERROR);
    }

    #[test]
    fn mixed_auth_and_config_returns_config_error() {
        // Both classes converge on configuration as the remediation, so a
        // mix of the two still promotes to CONFIG_ERROR.
        let rows = vec![row(Outcome::Auth), row(Outcome::Config)];
        assert_eq!(classify_exit_code(&rows), ExitCodes::CONFIG_ERROR);
    }

    #[test]
    fn inconclusive_does_not_block_specialized_code() {
        // A 404-at-probe-path alongside auth failures must still classify as
        // auth-only; the inconclusive entry has no signal either way.
        let rows = vec![row(Outcome::Inconclusive), row(Outcome::Auth)];
        assert_eq!(classify_exit_code(&rows), ExitCodes::CONFIG_ERROR);
    }
}
