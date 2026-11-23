use std::collections::HashSet;
use std::io;
use std::path::Path;
use std::time::Duration;

use clap::Args;

use rv_config::{AuthConfig, Config};
use rv_maven_types::Coord;
use rv_repo::{RepoClient, RepoError, Repository, normalize_repo_url};

use crate::error::{CliError, ErrorClass, ExitStatus, Result, report};
use crate::output::{CommandOutput, Human, Report, Table, WarningCode};
use crate::session::Session;

mod preflight;

const DOCTOR_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Args)]
#[command(after_long_help = crate::commands::util::help_examples(&[
    ("doctor", "Check the project, the store and every repository"),
    ("--offline doctor", "Check the project and the store only"),
    ("--json doctor", "Output as JSON"),
]))]
pub(crate) struct DoctorArgs {}

struct Row {
    check: String,
    details: String,
    outcome: Outcome,
    /// The stable code of a project check.
    code: Option<WarningCode>,
}

impl Row {
    fn new(check: impl Into<String>, details: impl Into<String>, outcome: Outcome) -> Self {
        Self {
            check: check.into(),
            details: details.into(),
            outcome,
            code: None,
        }
    }

    fn with_code(mut self, code: WarningCode) -> Self {
        self.code = Some(code);
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Ok,
    Inconclusive,
    /// Context for reading the other rows, never a pass or a failure.
    Info,
    /// Something about the project raeva does not lock as Maven builds it,
    /// which is not a failure.
    Warn,
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
            Outcome::Warn => "warn",
            Outcome::Config | Outcome::Auth | Outcome::Network | Outcome::Other => "fail",
        }
    }

    fn class(self) -> Option<&'static str> {
        match self {
            Outcome::Config => Some("config"),
            Outcome::Auth => Some("auth"),
            Outcome::Network => Some("network"),
            Outcome::Other => Some("other"),
            Outcome::Ok | Outcome::Inconclusive | Outcome::Info | Outcome::Warn => None,
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
            | ErrorClass::Internal
            | ErrorClass::Other => Outcome::Other,
        }
    }
}

pub(crate) async fn run(_args: &DoctorArgs, session: &Session) -> Result<Report> {
    let config = session.config_async().await?;
    let mut rows = vec![trust_roots_row(), store_row(&config.paths.store_dir)];
    let host = config.host();
    let [jvm_config, variables @ ..] = LAUNCH_OPTIONS;
    // `mvn`'s own variables, and the JVM's.
    let variables = variables.map(|name| match name {
        "_JAVA_OPTIONS" => (name, host.launcher_env(name)),
        name => (name, host.launcher_variable(name)),
    });
    let launch_options: Vec<(&str, &str)> = (config.jvm_config().map(|text| (jvm_config, text)))
        .into_iter()
        .chain((variables.iter()).filter_map(|(name, text)| Some((*name, (*text)?))))
        .collect();
    rows.extend(java4shell_row(
        host.jdk_release(),
        host.java_home(),
        rv_maven_model::avx512_vbmi_cpu(),
        &launch_options,
    ));
    // The project checks read local files only, before any request.
    let preflight = preflight::check(&config, session.offline());
    rows.extend(preflight.rows);

    if session.offline() {
        rows.push(Row::new(
            "repositories",
            "not probed offline",
            Outcome::Info,
        ));
    } else {
        // A real `RepoClient` applies what a sync applies: mirrors,
        // credentials, proxies and the redirect policy.
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
    }

    let failed = rows.iter().filter(|row| row.outcome.is_failure()).count();
    let status = classify_exit_code(&rows);
    let report = Report::data(DoctorReport {
        rows,
        snippets: preflight.snippets,
    });
    if failed > 0 {
        Ok(report.failed(CliError::DoctorChecksFailed { failed, status }))
    } else {
        Ok(report)
    }
}

struct DoctorReport {
    rows: Vec<Row>,
    snippets: Vec<preflight::Snippet>,
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
                    "code": row.code.map(WarningCode::as_str),
                    "details": row.details,
                })
            })
            .collect();
        let snippets: Vec<_> = (self.snippets.iter())
            .map(|snippet| serde_json::json!({"file": snippet.file, "text": snippet.text}))
            .collect();
        Ok(serde_json::json!({
            "issues": self.rows.iter().filter(|row| row.outcome.is_failure()).count(),
            "checks": checks,
            "snippets": snippets,
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
        let warned = (self.rows.iter())
            .filter(|row| row.outcome == Outcome::Warn)
            .count();
        if warned > 0 {
            human.note(format!(
                "{warned} check(s) warn; a warning does not change the exit status"
            ))?;
        }
        for snippet in &self.snippets {
            human.blank_line()?;
            human.heading(format!("for {}", snippet.file))?;
            for line in snippet.text.lines() {
                human.line(format!("  {line}"))?;
            }
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

/// The date of the JDK security update for CVE-2026-114938 (Java4Shell).
const JAVA4SHELL_UPDATE: &str = "2026-11-17";

/// A warning when the host JDK may carry CVE-2026-114938 (Java4Shell), the
/// memory corruption in HotSpot's x86-64 Base64 decoder intrinsic: on a CPU
/// with the instructions it uses, `vbmi`, for a JDK of 17.0.6 or later that
/// its `release` file dates before the update. Without a date raeva can
/// read, or with the intrinsic off in the options `mvn` passes, the row is
/// `info`; dated on or after the update, there is none, which says nothing
/// of whether that JDK is fixed. An OpenJ9 JDK, whose JVM is not HotSpot,
/// gets none.
fn java4shell_row(
    release: Option<&rv_maven_model::JdkRelease>,
    java_home: Option<&str>,
    vbmi: bool,
    launch_options: &[(&'static str, &str)],
) -> Option<Row> {
    let release = release.filter(|release| vbmi && !release.openj9)?;
    if release.version_numbers()? < vec![17, 0, 6] {
        return None;
    }
    let version = release.version.as_deref()?.trim();
    let jdk = match java_home {
        Some(home) => format!("JDK {version} at {home}"),
        None => format!("JDK {version}"),
    };
    let exposed = format!(
        "{jdk} may be affected by CVE-2026-114938 (Java4Shell) on this CPU, which has AVX-512 \
         VBMI, unless it carries the {JAVA4SHELL_UPDATE} security update"
    );
    let remedy = "update the JDK, or add -XX:-UseBASE64Intrinsics to MAVEN_OPTS or \
                  .mvn/jvm.config (https://github.com/raeva-io/raeva/blob/main/docs/ci.md#java4shell)";
    let date = (release.version_date.as_deref())
        .map(str::trim)
        .filter(|date| is_iso_date(date));
    let off = base64_intrinsic_off(launch_options);
    let (details, outcome) = match (date, off) {
        (Some(date), _) if date >= JAVA4SHELL_UPDATE => return None,
        (_, Some((option, source))) => (
            format!(
                "{exposed}. {option} in {source} turns the intrinsic off in the JVM mvn starts, \
                 but a JVM the build forks, such as Surefire's, may not get it: update the JDK"
            ),
            Outcome::Info,
        ),
        (Some(date), None) => (
            format!(
                "{exposed}; its JAVA_VERSION_DATE is {date}. A JVM it runs can be compromised \
                 through a TLS connection to a malicious server, such as a repository Maven \
                 fetches from: {remedy}"
            ),
            Outcome::Warn,
        ),
        (None, None) => (
            format!(
                "{exposed}, and its release file gives no JAVA_VERSION_DATE that tells; if it \
                 lacks the update, {remedy}"
            ),
            Outcome::Info,
        ),
    };
    Some(Row::new("JDK", details, outcome).with_code(WarningCode::HostJdkJava4shell))
}

/// Where the JVM `mvn` starts reads options, in the order it reads them:
/// `bin/mvn` and `mvn.cmd` pass `.mvn/jvm.config`, `MAVEN_OPTS` and
/// `MAVEN_DEBUG_OPTS`, and HotSpot reads `_JAVA_OPTIONS` after them.
const LAUNCH_OPTIONS: [&str; 4] = [
    ".mvn/jvm.config",
    "MAVEN_OPTS",
    "MAVEN_DEBUG_OPTS",
    "_JAVA_OPTIONS",
];

/// The option, and where it is set, that leaves HotSpot's AVX-512 Base64
/// decoder out of the JVM `mvn` starts, from `options` as named in
/// [`LAUNCH_OPTIONS`] and in that order: `-XX:-UseBASE64Intrinsics`, or
/// `-XX:UseAVX=` 0 to 2, which goes without AVX-512. The last option that
/// sets a flag wins. Text is split where `bin/mvn` splits it, and an option
/// that turns the intrinsic off counts only where no quote can make it part
/// of another: `mvn.cmd` and `_JAVA_OPTIONS` keep quoted text together.
fn base64_intrinsic_off<'a>(
    options: &[(&'static str, &'a str)],
) -> Option<(&'a str, &'static str)> {
    let (mut intrinsic, mut avx) = (None, None);
    for &(source, text) in options {
        // `tr` turns the line ends of `.mvn/jvm.config` into spaces.
        let separators: &[char] = match source {
            ".mvn/jvm.config" => &[' ', '\t', '\n', '\r'],
            _ => &[' ', '\t', '\n'],
        };
        let quoting = cfg!(windows) || source == "_JAVA_OPTIONS";
        let counts = !(quoting && text.contains(['"', '\'']));
        for raw in text.split(separators) {
            // The JVM drops quotes it reads, so an option they split still
            // turns the intrinsic on.
            let unquoted;
            let option = if counts {
                raw
            } else {
                unquoted = raw.replace(['"', '\''], "");
                unquoted.as_str()
            };
            match option {
                "-XX:-UseBASE64Intrinsics" if counts => intrinsic = Some(Some((raw, source))),
                "-XX:+UseBASE64Intrinsics" => intrinsic = Some(None),
                _ => {
                    let Some(level) = option.strip_prefix("-XX:UseAVX=") else {
                        continue;
                    };
                    match level.parse::<u8>() {
                        Ok(level) if level < 3 => {
                            if counts {
                                avx = Some(Some((raw, source)));
                            }
                        }
                        _ => avx = Some(None),
                    }
                }
            }
        }
    }
    intrinsic.flatten().or(avx.flatten())
}

/// Whether `date` is `YYYY-MM-DD`, which compares as text in date order.
fn is_iso_date(date: &str) -> bool {
    date.len() == 10
        && (date.bytes().enumerate()).all(|(at, b)| {
            if at == 4 || at == 7 {
                b == b'-'
            } else {
                b.is_ascii_digit()
            }
        })
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
    let client = crate::commands::sync::Mode::probe()
        .client(&probe_config)
        .await?;
    Ok((client, cache_dir))
}

struct ProbeTarget {
    repository: Repository,
    declared_in: Option<String>,
    /// A plugin repository: of settings.xml, which plugin locking reads, or
    /// of a project POM (`declared_in`).
    plugins: bool,
}

/// What a probe is asked once for: sync lists one URL under each of its
/// ids, each with its own mirror and credential.
fn probe_key(url: &str, id: &Option<String>) -> (String, Option<String>) {
    (normalize_repo_url(url), id.clone())
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
            plugins: false,
        })
        .collect();
    let mut refused_rows = Vec::new();
    // Sync trusts these as the user's own declarations, and refuses a URL
    // with userinfo, a query or a fragment, or plain HTTP to another host.
    // Doctor must too: admit screens those out, and only admitted targets
    // are probed. The project's plugin repositories are here when sync
    // refuses them or, with the plugins locked, reads them.
    let secrets = config.secret_named_inputs();
    let names = config.secret_input_names();
    for target in declared {
        let path = target.declared_in.as_deref().unwrap_or("pom.xml");
        let label = target.repository.id.as_deref().unwrap_or("repository");
        let label = format!(
            "{} ({path})",
            rv_repo::shown_id(label, target.repository.id_reads(), &secrets, &names)
        );
        let element = match target.plugins {
            true => "<pluginRepository>",
            false => "<repository>",
        };
        let id = target.repository.id.as_deref();
        let repository = &target.repository;
        let reads = repository.url_reads();
        let refusal = match rv_repo::secret_url_refusal(&repository.url, reads, &secrets, &names) {
            Some(refusal) => Some(format!("a {element} URL declared in {path} {refusal}")),
            None => rv_repo::secret_id_refusal(id, repository.id_reads(), &secrets, &names)
                .map(|refusal| format!("a {element} id declared in {path} {refusal}")),
        };
        if let Some(refusal) = refusal {
            refused_rows.push(Row::new(label, refusal, Outcome::Config));
            continue;
        }
        let admission =
            (client.policy()).admit([target.repository.clone()], rv_repo::Declaration::LocalPom);
        if !admission.blocked_http.is_empty() {
            refused_rows.push(Row::new(
                label,
                "plain HTTP, which sync ignores, as Maven's HTTP blocker does; name the same \
                 URL in raeva.toml, config.toml or settings.xml, or a mirror for it, to use it",
                Outcome::Inconclusive,
            ));
        }
        targets.extend(
            (admission.admitted.into_iter()).map(|repository| ProbeTarget {
                declared_in: target.declared_in.clone(),
                repository,
                plugins: target.plugins,
            }),
        );
    }
    if config.plugins.is_some() {
        let mut seen: HashSet<(String, Option<String>)> = (targets.iter())
            .map(|target| probe_key(&target.repository.url, &target.repository.id))
            .collect();
        // As plugin resolution reads them, the first of an id only.
        let mut ids = HashSet::new();
        let plugin_targets: Vec<ProbeTarget> = (config.profile_plugin_repositories().iter())
            .chain(config.plugin_repositories())
            .filter(|repo| repo.id.as_ref().is_none_or(|id| ids.insert(id.clone())))
            .filter(|repo| seen.insert(probe_key(&repo.url, &repo.id)))
            .map(|repo| ProbeTarget {
                repository: Repository::from(repo),
                declared_in: None,
                plugins: true,
            })
            .collect();
        targets.extend(plugin_targets);
    }
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
/// already name, with the plugin repositories they declare that sync
/// refuses or, with the plugins locked, reads, in reactor order and each URL once under each id, and the URLs of
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
            && !(defaults.iter()).any(|other| normalize_repo_url(&other.url) == repository.url)
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
                && (targets.iter().flatten()).all(|(_, declared, _)| {
                    declared
                        .iter()
                        .any(|repository| replaces(default, repository))
                })
        })
        .map(|default| normalize_repo_url(&default.url))
        .collect();
    let mut seen: HashSet<(String, Option<String>)> = (config.repositories().iter())
        .map(|repo| probe_key(&repo.url, &repo.id))
        .collect();
    let secrets = config.secret_named_inputs();
    let names = config.secret_input_names();
    // Plugin resolution reads the settings.xml profiles' plugin
    // repositories first, and a module's only under another id.
    let settings_ids: HashSet<&str> = (config.profile_plugin_repositories().iter())
        .filter_map(|repo| repo.id.as_deref())
        .collect();
    let read_by_sync = |repo: &Repository| {
        config.plugins.is_some() && (repo.id.as_deref()).is_none_or(|id| !settings_ids.contains(id))
    };
    let mut declared = Vec::new();
    for (path, repositories, plugin_repositories) in targets.into_iter().flatten() {
        let read = (plugin_repositories.into_iter()).filter(|repo| {
            read_by_sync(repo)
                || rv_repo::secret_url_refusal(&repo.url, repo.url_reads(), &secrets, &names)
                    .is_some()
                || rv_repo::secret_id_refusal(repo.id.as_deref(), repo.id_reads(), &secrets, &names)
                    .is_some()
        });
        let tagged = (repositories.into_iter().map(|repo| (repo, false)))
            .chain(read.map(|repo| (repo, true)));
        for (repository, plugins) in tagged {
            if seen.insert(probe_key(&repository.url, &repository.id)) {
                declared.push(ProbeTarget {
                    repository,
                    declared_in: Some(path.clone()),
                    plugins,
                });
            }
        }
    }
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
    let plugins = target.plugins.then(|| "plugin repository".to_string());
    let notes: Vec<String> = (target.declared_in.iter().cloned())
        .chain(plugins)
        .chain(mirror)
        .collect();
    if !notes.is_empty() {
        label.push_str(&format!(" ({})", notes.join(", ")));
    }

    // Neither the URL nor its scheme is shown: either may come from a
    // secret's variable.
    if !(route.endpoint.base_url())
        .is_ok_and(|url| matches!(url.scheme(), "http" | "https" | "file"))
    {
        return Row::new(
            label,
            "no http, https or file URL that raeva can read, so sync's requests to it fail and \
             it searches the other repositories, as Maven does",
            Outcome::Warn,
        );
    }
    if (route.mirror.as_ref()).is_some_and(|mirror| {
        mirror.blocked && mirror.id.as_deref() == Some(rv_repo::HTTP_BLOCKER_ID)
    }) {
        return Row::new(
            label,
            "plain HTTP, which Maven's HTTP blocker blocks, so sync sends it no requests and \
             searches the other repositories; mirror it or give an https URL",
            Outcome::Warn,
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
            // The directory may hold a secret a mirror URL takes.
            match rv_config::url_holds_secret(url.as_str()) {
                true => format!("{} is not a directory", rv_config::redact_url(url.as_str())),
                false => format!("{} is not a directory", dir.display()),
            },
            Outcome::Config,
        );
    }
    let path = probe_metadata_path(&coord);
    let withheld = scope_withholds(config, &route.endpoint);
    let credential = withheld.is_none().then(|| {
        credential_source(
            config.auth(),
            &route.endpoint,
            route.cross_origin || !user_origins.contains(&http_origin(&route.endpoint.url)),
        )
    });
    let credential = credential.flatten();
    let (mut details, outcome) = match client.fetch_metadata(origin, &coord).await {
        Ok(_) => match &credential {
            Some(credential) => (
                format!("served {path} with {}", credential.label()),
                Outcome::Ok,
            ),
            None => (format!("served {path}"), Outcome::Ok),
        },
        Err(err) => {
            let hints = crate::error::HintEnv::for_config(config);
            let settings = hints.settings_location();
            let unset =
                (credential.as_ref()).map_or_else(Vec::new, |sent| unset_variables(config, sent));
            let credential = credential
                .as_ref()
                .map(|credential| (credential, &unset[..]));
            let dropped = (route.endpoint.id.as_deref()).filter(|id| hints.password_dropped(id));
            let unsent = match (withheld, dropped) {
                (Some(id), _) => scope_hint(id),
                (None, Some(_)) => format!(
                    "the encrypted password of the settings.xml server with this id could not \
                     be decrypted; give raeva the settings-security.xml with its master password \
                     or write the password as ${{env.NAME}} in {settings}"
                ),
                (None, None) => missing_credential_hint(&route.endpoint, &settings),
            };
            classify_probe_error(err, &path, &settings, credential, &unsent)
        }
    };
    // The mirror stands in for Central when it is the one Central routes to.
    let central = Repository::new(
        Some("central".to_string()),
        "https://repo.maven.apache.org/maven2/",
        true,
        false,
    );
    let of_central = |mirror: &rv_config::MirrorConfig| {
        (client.route(&central).mirror)
            .is_some_and(|routed| routed.id == mirror.id && routed.url == mirror.url)
    };
    if outcome == Outcome::Inconclusive && route.mirror.as_ref().is_some_and(of_central) {
        details.push_str(
            "; if this mirror is a private registry that does not proxy Maven Central, declare \
             it as a repository next to Central instead of a mirror",
        );
    }
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
    // The first entry with the id that answers: a `<server>` whose password
    // was dropped answers with no credential, and the default does not
    // answer in its place.
    if let Some(id) = resolved.id.as_deref()
        && let Some(entry) = (auth.iter())
            .filter(|entry| entry.id.as_deref() == Some(id))
            .find(|entry| entry.password_dropped || usable(entry))
    {
        return (!entry.password_dropped).then(|| CredentialSource::ConfigId(id.to_string()));
    }
    if withhold_default {
        return None;
    }
    auth.iter()
        .filter(|entry| usable(entry))
        .find(|entry| entry.id.is_none())
        .map(|_| CredentialSource::ConfigDefault)
}

fn usable(entry: &AuthConfig) -> bool {
    entry.token.is_some() || (entry.username.is_some() && entry.password.is_some())
}

/// The variables of the `${env.NAME}` references in the settings.xml
/// `<server>` that `sent` names, which settings.xml leaves as written when
/// they are unset, as rv-repo reports them for a 401. Names only: no value
/// is shown.
fn unset_variables(config: &Config, sent: &CredentialSource) -> Vec<String> {
    use secrecy::ExposeSecret;
    let id = match sent {
        CredentialSource::ConfigId(id) => Some(id.as_str()),
        CredentialSource::ConfigDefault => None,
    };
    let auth = config.auth();
    let layers = config.auth_layers();
    let Some(entry) = (auth.iter().enumerate())
        .find(|(_, entry)| usable(entry) && entry.id.as_deref() == id)
        .filter(|(index, _)| *index >= layers.project().len() + layers.user().len())
        .map(|(_, entry)| entry)
    else {
        return Vec::new();
    };
    let texts = match &entry.token {
        Some(token) => vec![token.expose_secret()],
        None => (entry.username.as_deref().into_iter())
            .chain(entry.password.as_ref().map(ExposeSecret::expose_secret))
            .collect(),
    };
    let mut names = Vec::new();
    for name in texts.into_iter().flat_map(rv_config::unset_env_references) {
        if !names.contains(&name) {
            names.push(name);
        }
    }
    names
}

/// The id of the settings.xml server whose username and password sync
/// keeps from `resolved` in the Maven 3.10 mode, as Maven's credential
/// scope does.
fn scope_withholds<'a>(config: &Config, resolved: &'a Repository) -> Option<&'a str> {
    let id = resolved.id.as_deref()?;
    (crate::error::HintEnv::for_config(config).scope_withholds(id, &resolved.url)).then_some(id)
}

/// Why a username and password [`scope_withholds`] were not sent. The
/// origin is not shown: sync's `ID_CREDENTIAL_WITHHELD` warning names it
/// masked.
fn scope_hint(id: &str) -> String {
    format!(
        "the username and password of the settings.xml server '{}' are withheld, as Maven \
         3.10 binds them to the origins of the mirrors and repositories settings.xml gives \
         that id and of the server's <repositoryOrigins>; add this repository's origin there \
         if they belong to it, or set maven.repository.credentialScope=id",
        crate::output::inline_text(id)
    )
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
/// 404 says whether `credential` was sent, with the unset variables it
/// names, as some repositories answer a wrong one with 404.
fn classify_probe_error(
    err: RepoError,
    path: &str,
    settings: &str,
    credential: Option<(&CredentialSource, &[String])>,
    unsent: &str,
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
                None => format!("{code} (no credentials were sent; {unsent})"),
            };
            (details, Outcome::Auth)
        }
        Some(407) => (
            "407 (proxy authentication required; check proxy credentials)".to_string(),
            Outcome::Auth,
        ),
        Some(404) => {
            let (sent, unchecked) = match credential {
                Some((credential, unset)) => (
                    match report::unset_variables_note(unset) {
                        Some(note) => {
                            format!("{} were sent; {note} from {settings}", credential.label())
                        }
                        None => format!("{} were sent", credential.label()),
                    },
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
                     check it by fetching a file you know it holds, such as one you published; \
                     a raeva sync that the store already answers sends no request"
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
    use crate::output::WarningCode;
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
                (rv_config::MAVEN_USER_HOME_TEST_ENV, Some(root)),
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

    /// The Java4Shell row needs each of an AVX-512 VBMI CPU, a JDK of
    /// 17.0.6 or later and a `JAVA_VERSION_DATE` before the update: it
    /// warns with all three, is `info` without a date it can read, and is
    /// left out otherwise.
    #[test]
    fn the_java4shell_row_needs_the_cpu_the_jdk_and_its_date() {
        let release = |version: &str, date: Option<&str>| rv_maven_model::JdkRelease {
            version: Some(version.to_string()),
            version_date: date.map(str::to_string),
            openj9: false,
        };
        let row = |release: rv_maven_model::JdkRelease, vbmi: bool| {
            super::java4shell_row(Some(&release), Some("/opt/jdk"), vbmi, &[])
                .map(|row| (row.outcome, row.code, row.details))
        };
        let before = Some("2026-10-21");
        for version in ["17.0.6", "17.0.21.0.3", "21.0.9", "25", "27.0.1+3"] {
            let (outcome, code, details) = row(release(version, before), true).expect(version);
            assert_eq!(outcome, Outcome::Warn, "{version}");
            assert_eq!(code, Some(WarningCode::HostJdkJava4shell));
            for part in [
                &format!("JDK {version} at /opt/jdk"),
                "CVE-2026-114938",
                "unless it carries the 2026-11-17 security update",
                "JAVA_VERSION_DATE is 2026-10-21",
                "-XX:-UseBASE64Intrinsics to MAVEN_OPTS or .mvn/jvm.config",
                "update the JDK",
            ] {
                assert!(details.contains(part), "{part}: {details}");
            }
            // A CPU without AVX-512 VBMI, or not x86-64, gets no row.
            assert_eq!(row(release(version, before), false), None, "{version}");
        }
        for version in ["17.0.5", "17", "11.0.25", "1.8.0_511", "", "x"] {
            assert_eq!(row(release(version, before), true), None, "{version}");
        }
        for date in ["2026-11-17", "2026-12-01", "2027-01-20"] {
            assert_eq!(row(release("21.0.10", Some(date)), true), None, "{date}");
        }
        for date in [None, Some(""), Some("2026-10"), Some("21 Oct 2026")] {
            let (outcome, code, details) = row(release("21.0.9", date), true).expect("info");
            assert_eq!(outcome, Outcome::Info, "{date:?}");
            assert_eq!(code, Some(WarningCode::HostJdkJava4shell));
            assert!(details.contains("no JAVA_VERSION_DATE"), "{details}");
            assert!(!details.contains("safe"), "{details}");
            assert_eq!(row(release("21.0.9", date), false), None);
        }
        assert!(super::java4shell_row(None, None, true, &[]).is_none());
    }

    /// An OpenJ9 JDK, as IBM Semeru's `release` file names it, gets no row:
    /// the flaw is in HotSpot. The same file without the OpenJ9 lines warns.
    #[test]
    fn the_java4shell_row_leaves_out_an_openj9_jdk() {
        let semeru = "IMPLEMENTOR=\"IBM Corporation\"\n\
                      IMPLEMENTOR_VERSION=\"21.0.13.0\"\n\
                      JAVA_RUNTIME_VERSION=\"21.0.13.0.3+1-LTS\"\n\
                      JAVA_VERSION=\"21.0.13.0.3\"\n\
                      JAVA_VERSION_DATE=\"2026-10-24\"\n\
                      LIBC=\"gnu\"\n\
                      MODULES=\"java.base java.se openj9.jvm openj9.sharedclasses\"\n\
                      OS_ARCH=\"x86_64\"\n\
                      OS_NAME=\"Linux\"\n\
                      SOURCE=\"OpenJDK:62d1b70e191 OpenJ9:dcc7ee16aa OMR:c2a3a9ae0\"\n\
                      BUILD_TYPE=\"commercial\"\n\
                      JVM_VARIANT=\"Openj9\"\n\
                      JVM_VERSION=\"21.0.13.0.3+1-openj9-0.63.0\"\n\
                      IMAGE_TYPE=\"JDK\"\n";
        let release = rv_maven_model::JdkRelease::parse(semeru);
        assert!(release.openj9);
        let semeru_row = super::java4shell_row(Some(&release), Some("/opt/semeru"), true, &[]);
        assert!(semeru_row.is_none());
        let hotspot: String = (semeru.lines())
            .filter(|line| !line.to_ascii_lowercase().contains("openj9"))
            .map(|line| format!("{line}\n"))
            .collect();
        let release = rv_maven_model::JdkRelease::parse(&hotspot);
        assert!(!release.openj9);
        let row = super::java4shell_row(Some(&release), Some("/opt/jdk"), true, &[]);
        assert_eq!(row.expect("row").outcome, Outcome::Warn);
    }

    /// The JVM `mvn` starts takes `.mvn/jvm.config`, then `MAVEN_OPTS`, and
    /// the last option that sets a flag wins. With the intrinsic off, by
    /// `-XX:-UseBASE64Intrinsics` or a `-XX:UseAVX=` below 3, the row is
    /// `info` and names the option; otherwise it stays as it was.
    #[test]
    fn the_java4shell_row_reads_the_options_mvn_passes() {
        let release = |date: Option<&str>| rv_maven_model::JdkRelease {
            version: Some("21.0.9".to_string()),
            version_date: date.map(str::to_string),
            openj9: false,
        };
        let row = |date: Option<&str>, vbmi: bool, jvm_config: Option<&str>, opts: Option<&str>| {
            let release = release(date);
            let options = [(".mvn/jvm.config", jvm_config), ("MAVEN_OPTS", opts)];
            let options: Vec<_> = (options.into_iter())
                .filter_map(|(source, text)| Some((source, text?)))
                .collect();
            super::java4shell_row(Some(&release), Some("/opt/jdk"), vbmi, &options)
                .map(|row| (row.outcome, row.code, row.details))
        };
        let off = [
            (
                None,
                Some("-Xmx1g -XX:-UseBASE64Intrinsics"),
                "-XX:-UseBASE64Intrinsics in MAVEN_OPTS",
            ),
            (
                Some("-Xmx1g\r\n-XX:-UseBASE64Intrinsics\n"),
                None,
                "-XX:-UseBASE64Intrinsics in .mvn/jvm.config",
            ),
            (None, Some("-XX:UseAVX=2"), "-XX:UseAVX=2 in MAVEN_OPTS"),
            (
                Some("-XX:UseAVX=0"),
                Some("-Xmx1g"),
                "-XX:UseAVX=0 in .mvn/jvm.config",
            ),
            (
                Some("-XX:+UseBASE64Intrinsics"),
                Some("\t-XX:-UseBASE64Intrinsics"),
                "-XX:-UseBASE64Intrinsics in MAVEN_OPTS",
            ),
            (
                Some("-XX:-UseBASE64Intrinsics"),
                Some("-XX:+UseBASE64Intrinsics -XX:UseAVX=1"),
                "-XX:UseAVX=1 in MAVEN_OPTS",
            ),
        ];
        for date in [Some("2026-10-21"), None] {
            for (jvm_config, opts, named) in off {
                let (outcome, code, details) = row(date, true, jvm_config, opts).expect(named);
                assert_eq!(outcome, Outcome::Info, "{named}");
                assert_eq!(code, Some(WarningCode::HostJdkJava4shell));
                for part in [
                    "CVE-2026-114938",
                    named,
                    "turns the intrinsic off",
                    "Surefire",
                ] {
                    assert!(details.contains(part), "{part}: {details}");
                }
                assert_eq!(row(date, false, jvm_config, opts), None, "{named}");
            }
        }
        for (jvm_config, opts) in [
            (None, None),
            (Some(""), Some("-Xmx1g")),
            (
                Some("-XX:-UseBASE64Intrinsics"),
                Some("-XX:+UseBASE64Intrinsics"),
            ),
            (Some("-XX:UseAVX=2"), Some("-XX:UseAVX=3")),
            (None, Some("\"-XX:-UseBASE64Intrinsics\"")),
            (None, Some("-XX:-UseBASE64IntrinsicsX")),
            (None, Some("-XX:UseAVX= -XX:UseAVX=x")),
        ] {
            let (outcome, _, details) =
                row(Some("2026-10-21"), true, jvm_config, opts).expect("warn");
            assert_eq!(outcome, Outcome::Warn, "{jvm_config:?} {opts:?}");
            assert!(!details.contains("turns the intrinsic off"), "{details}");
        }
        let updated = row(
            Some("2026-11-17"),
            true,
            None,
            Some("-XX:-UseBASE64Intrinsics"),
        );
        assert_eq!(updated, None);
    }

    /// `MAVEN_DEBUG_OPTS` and `_JAVA_OPTIONS` come after `MAVEN_OPTS`, the
    /// shell splits at no space but its own, and a reader that keeps quoted
    /// text together may hold the option inside a value.
    #[test]
    fn the_java4shell_row_takes_the_options_as_the_jvm_reads_them() {
        let release = rv_maven_model::JdkRelease {
            version: Some("21.0.9".to_string()),
            version_date: Some("2026-10-21".to_string()),
            openj9: false,
        };
        let outcome = |options: &[(&'static str, &str)]| {
            super::java4shell_row(Some(&release), Some("/opt/jdk"), true, options)
                .expect("row")
                .outcome
        };
        let off = ("MAVEN_OPTS", "-XX:-UseBASE64Intrinsics");
        assert_eq!(outcome(&[off]), Outcome::Info);
        for later in ["MAVEN_DEBUG_OPTS", "_JAVA_OPTIONS"] {
            assert_eq!(
                outcome(&[off, (later, "-XX:+UseBASE64Intrinsics")]),
                Outcome::Warn
            );
            assert_eq!(outcome(&[off, (later, "-XX:UseAVX=3")]), Outcome::Info);
            let on = ("MAVEN_OPTS", "-XX:+UseBASE64Intrinsics");
            assert_eq!(
                outcome(&[on, (later, "-XX:-UseBASE64Intrinsics")]),
                Outcome::Info
            );
        }
        let joined = "-Dnote=x\u{a0}-XX:-UseBASE64Intrinsics\u{a0}y";
        assert_eq!(outcome(&[("MAVEN_OPTS", joined)]), Outcome::Warn);
        let quoted = "-Dnote=\"x -XX:-UseBASE64Intrinsics y\"";
        assert_eq!(outcome(&[("_JAVA_OPTIONS", quoted)]), Outcome::Warn);
        let expected = if cfg!(windows) {
            Outcome::Warn
        } else {
            Outcome::Info
        };
        assert_eq!(outcome(&[("MAVEN_OPTS", quoted)]), expected);
        // A quoted value does not hide an option before it.
        let earlier = [
            (".mvn/jvm.config", "-XX:-UseBASE64Intrinsics"),
            ("_JAVA_OPTIONS", quoted),
        ];
        assert_eq!(outcome(&earlier), Outcome::Info);
        // HotSpot drops the quotes of `_JAVA_OPTIONS`, so a quoted option
        // that turns the intrinsic back on still does.
        assert_eq!(
            outcome(&[off, ("_JAVA_OPTIONS", "\"-XX:+UseBASE64Intrinsics\"")]),
            Outcome::Warn
        );
        let avx = ("MAVEN_OPTS", "-XX:UseAVX=2");
        assert_eq!(
            outcome(&[avx, ("_JAVA_OPTIONS", "-XX:UseAVX='3'")]),
            Outcome::Warn
        );
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

    /// In the Maven 3.10 mode, the settings.xml username and password that
    /// Maven's credential scope keeps from a repository are not reported as
    /// sent, and a 401 names the scope rather than a missing `<server>`. A
    /// raeva.toml entry for the id whose first one is empty leaves it to
    /// settings.xml, as sync does.
    #[tokio::test]
    async fn a_credential_the_scope_withholds_is_not_reported_as_sent() {
        let authorized = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let seen = authorized.clone();
        let server = StubServer::start(move |request| {
            if request.header("authorization").is_some() {
                seen.store(true, std::sync::atomic::Ordering::SeqCst);
            }
            match request.path.starts_with("/locked/") {
                true => Response::new(401, ""),
                false => Response::new(404, ""),
            }
        });
        let root = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(root.path().join(".m2")).expect(".m2");
        let server_entry = |id: &str| {
            format!(
                "<server><id>{id}</id><username>u</username><password>p</password>\
                 <repositoryOrigins><repositoryOrigin>https://elsewhere.example\
                 </repositoryOrigin></repositoryOrigins></server>"
            )
        };
        std::fs::write(
            root.path().join(".m2/settings.xml"),
            format!(
                "<settings><servers>{}{}</servers></settings>",
                server_entry("locked"),
                server_entry("open")
            ),
        )
        .expect("settings.xml");
        let rows = probe_project(
            root.path(),
            "raeva.toml",
            &format!(
                "[lock]\nmaven = \"3.10\"\n\n[[repositories]]\nid = \"locked\"\n\
                 url = \"http://{0}/locked/\"\n\n[[repositories]]\nid = \"open\"\n\
                 url = \"http://{0}/open/\"\n{1}\n[[auth]]\nid = \"open\"\n\n\
                 [[auth]]\nid = \"open\"\ntoken = \"t\"\n",
                server.addr(),
                local_central(&server),
            ),
        )
        .await;
        server.stop();
        assert!(!authorized.load(std::sync::atomic::Ordering::SeqCst));
        let row = |id: &str| {
            (rows.iter())
                .find(|row| row.check.starts_with(id))
                .unwrap_or_else(|| panic!("no {id} row"))
        };
        let locked = &row("locked").details;
        assert_eq!(row("locked").outcome, Outcome::Auth, "{locked}");
        assert!(
            locked.contains("credentialScope") && !locked.contains("add a <server>"),
            "{locked}"
        );
        let open = &row("open").details;
        assert!(open.contains("(no credentials were sent)"), "{open}");
    }

    /// A repository whose URL raeva cannot read, which sync skips with a
    /// warning as Maven does, is a warning rather than a network failure,
    /// and its scheme is not shown.
    #[tokio::test]
    async fn a_url_raeva_cannot_read_is_a_warning() {
        let central = StubServer::start(|_| Response::new(404, ""));
        let root = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(root.path().join(".m2")).expect(".m2");
        std::fs::write(
            root.path().join(".m2/settings.xml"),
            "<settings><profiles><profile><id>p</id><repositories>\
             <repository><id>odd</id><url>secret://repo.example/maven2/</url></repository>\
             <repository><id>broken</id><url>https://[secret</url></repository>\
             </repositories></profile></profiles><activeProfiles><activeProfile>p\
             </activeProfile></activeProfiles></settings>",
        )
        .expect("settings.xml");
        let rows = probe_project(root.path(), "raeva.toml", &local_central(&central)).await;
        central.stop();
        for id in ["odd", "broken"] {
            let row = (rows.iter())
                .find(|row| row.check.starts_with(id))
                .unwrap_or_else(|| panic!("no {id} row"));
            assert_eq!(row.outcome, Outcome::Warn, "{}", row.details);
            assert!(!row.details.contains("secret"), "{}", row.details);
        }
    }

    /// A 404 for the probe file checks nothing, since some repositories
    /// answer a wrong credential with 404 too: the row says whether
    /// credentials were sent and how to check the repository instead.
    #[tokio::test]
    async fn a_404_says_what_it_leaves_unchecked() {
        let server = StubServer::start(|_| Response::new(404, ""));
        let root = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(root.path().join(".m2")).expect("mkdir");
        std::fs::write(
            root.path().join(".m2/settings.xml"),
            "<settings><servers><server><id>env</id><username>u</username>\
             <password>${env.RAEVA_DOCTOR_UNSET_TOKEN}</password></server></servers></settings>",
        )
        .expect("write settings.xml");
        let rows = probe_project(
            root.path(),
            "config.toml",
            &format!(
                "[[repositories]]\nid = \"corp\"\nurl = \"http://{0}/corp/\"\n\
                 [[repositories]]\nid = \"open\"\nurl = \"http://{0}/open/\"\n\
                 [[repositories]]\nid = \"env\"\nurl = \"http://{0}/env/\"\n{1}\n\
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
                     credentials are checked; check it by fetching a file you know it holds, \
                     such as one you published; a raeva sync that the store already answers \
                     sends no request"
                ),
            ),
            (
                "open",
                format!(
                    "404 for the org.apache:maven metadata at {path} (no credentials were \
                     sent), so the repository's content is not checked; check it by fetching \
                     a file you know it holds, such as one you published; a raeva sync that the \
                     store already answers sends no request"
                ),
            ),
            // As for a 401, the row names a variable settings.xml left unset.
            (
                "env",
                format!(
                    "404 for the org.apache:maven metadata at {path} (credentials for id 'env' \
                     were sent; RAEVA_DOCTOR_UNSET_TOKEN is not set, so the repository received \
                     the literal text ${{env.RAEVA_DOCTOR_UNSET_TOKEN}} from {}), so neither \
                     the repository's content nor the credentials are checked; check it by \
                     fetching a file you know it holds, such as one you published; a raeva sync \
                     that the store already answers sends no request",
                    root.path().join(".m2").join("settings.xml").display()
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

    /// A 404 through a mirror of Central may mean the mirror is a private
    /// registry that does not proxy Central: that row, and only that one,
    /// says so, and stays inconclusive. Whether the mirror serves Central
    /// is the router's answer, so `*,!central` does not.
    #[tokio::test]
    async fn a_404_through_a_mirror_of_central_names_the_mirror_choice() {
        const NOTE: &str = "if this mirror is a private registry that does not proxy Maven \
                            Central, declare it as a repository next to Central instead of a \
                            mirror";
        let server = StubServer::start(|_| Response::new(404, ""));
        for (mirror_of, noted) in [
            ("'central'", true),
            ("'*'", true),
            ("'corp'", false),
            ("'*,!central'", false),
        ] {
            let root = tempfile::tempdir().expect("tempdir");
            let rows = probe_project(
                root.path(),
                "config.toml",
                &format!(
                    "[[repositories]]\nid = \"corp\"\nurl = \"http://{0}/corp/\"\n{1}\n\
                     [[mirrors]]\nid = \"reg\"\nurl = \"http://{0}/reg/\"\n\
                     mirror_of = [{mirror_of}]\n",
                    server.addr(),
                    local_central(&server),
                ),
            )
            .await;
            let mirrored: Vec<_> = (rows.iter())
                .filter(|row| row.check.contains("via mirror reg"))
                .collect();
            assert!(!mirrored.is_empty(), "{mirror_of}");
            for row in rows.iter().filter(|row| row.details.starts_with("404")) {
                assert_eq!(row.outcome, Outcome::Inconclusive, "{}", row.details);
                let expected = noted && row.check.contains("via mirror reg");
                assert_eq!(
                    row.details.ends_with(NOTE),
                    expected,
                    "{mirror_of}: {}",
                    row.details
                );
            }
        }
        server.stop();
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
        let plugin_repository = (pom_repository("leaky-plugins", &secret_url))
            .replace("repository>", "pluginRepository>");
        std::fs::write(
            root.path().join("pom.xml"),
            pom("app", &pom_repository("leaky", &secret_url), "").replace(
                "</project>",
                &format!("<pluginRepositories>{plugin_repository}</pluginRepositories></project>"),
            ),
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
        // Sync refuses either, so doctor fails on both.
        for (id, element) in [
            ("leaky ", "<repository>"),
            ("leaky-plugins", "<pluginRepository>"),
        ] {
            let leaky = rows
                .iter()
                .find(|row| row.check.starts_with(id))
                .unwrap_or_else(|| panic!("no {id} row"));
            assert_eq!(leaky.outcome, Outcome::Config, "{}", leaky.details);
            assert!(
                leaky.details.contains("userinfo")
                    && leaky.details.contains("pom.xml")
                    && leaky.details.contains(element),
                "{}",
                leaky.details
            );
        }
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

    /// Plugin locking reads the settings.xml and project plugin
    /// repositories, so doctor probes them then, each URL once, and as
    /// sync, only the first of an id: Central's URL is not asked when a
    /// profile replaces it.
    #[tokio::test]
    async fn plugin_repositories_are_probed_when_plugins_are_locked() {
        let server = StubServer::start(|_request| Response::new(404, ""));
        let root = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            root.path().join("pom.xml"),
            "<project><modelVersion>4.0.0</modelVersion><groupId>g</groupId>\
             <artifactId>a</artifactId><version>1</version><pluginRepositories>\
             <pluginRepository><id>pom-plugins</id><url>https://pom.example.com/plugins/</url>\
             </pluginRepository></pluginRepositories></project>",
        )
        .expect("write pom.xml");
        std::fs::create_dir_all(root.path().join(".m2")).expect("mkdir");
        std::fs::write(
            root.path().join(".m2/settings.xml"),
            format!(
                "<settings><mirrors><mirror><id>all</id><mirrorOf>*</mirrorOf>\
                 <url>http://{}/all/</url></mirror></mirrors>\
                 <profiles><profile><id>corp</id><pluginRepositories><pluginRepository>\
                 <id>corp-plugins</id><url>https://plugins.example.com/maven2/</url>\
                 </pluginRepository></pluginRepositories></profile><profile><id>own</id>\
                 <activation><activeByDefault>true</activeByDefault></activation>\
                 <repositories><repository><id>central</id>\
                 <url>https://own.example.com/maven2/</url></repository></repositories>\
                 <pluginRepositories><pluginRepository><id>central</id>\
                 <url>https://own.example.com/plugins/</url></pluginRepository>\
                 </pluginRepositories></profile></profiles>\
                 <activeProfiles><activeProfile>corp</activeProfile></activeProfiles>\
                 </settings>",
                server.addr()
            ),
        )
        .expect("write settings.xml");
        let checks = |rows: Vec<Row>| -> Vec<String> {
            rows.into_iter()
                .filter(|row| row.check != "project repositories")
                .map(|row| row.check)
                .collect()
        };
        let unlocked = checks(probe_project(root.path(), "raeva.toml", "").await);
        let locked =
            checks(probe_project(root.path(), "raeva.toml", "[plugins]\nlock = true\n").await);
        server.stop();
        assert_eq!(unlocked, ["central (via mirror all)"]);
        assert_eq!(
            locked,
            [
                "central (via mirror all)",
                "pom-plugins (pom.xml, plugin repository, via mirror all)",
                "central (plugin repository, via mirror all)",
                "corp-plugins (plugin repository, via mirror all)"
            ]
        );
    }

    /// Sync keeps a URL under each of its ids, each with its own mirror and
    /// credential, so doctor asks it under each, and once under one id.
    #[tokio::test]
    async fn a_url_under_another_id_is_probed_under_each() {
        let server = StubServer::start(|_request| Response::new(404, ""));
        let url = format!("http://{}/central/", server.addr());
        let root = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            root.path().join("pom.xml"),
            pom("app", &pom_repository("corp-team", &url), ""),
        )
        .expect("write pom.xml");
        std::fs::create_dir_all(root.path().join(".m2")).expect("mkdir");
        std::fs::write(
            root.path().join(".m2/settings.xml"),
            format!(
                "<settings><profiles><profile><id>corp</id><pluginRepositories>\
                 <pluginRepository><id>corp-plugins</id><url>{url}</url></pluginRepository>\
                 <pluginRepository><id>central</id><url>{url}</url></pluginRepository>\
                 </pluginRepositories></profile></profiles>\
                 <activeProfiles><activeProfile>corp</activeProfile></activeProfiles>\
                 </settings>"
            ),
        )
        .expect("write settings.xml");
        let configured = format!("{}[plugins]\nlock = true\n", local_central(&server));
        let rows = probe_project(root.path(), "raeva.toml", &configured).await;
        server.stop();
        let mut checks: Vec<&str> = rows.iter().map(|row| row.check.as_str()).collect();
        checks.retain(|check| *check != "project repositories");
        assert_eq!(
            checks,
            [
                "central",
                "corp-team (pom.xml)",
                "corp-plugins (plugin repository)"
            ]
        );
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

    /// The project's own copy of a repository that a profile turned off by
    /// `-P !id` names leaves it probed once, however the URLs end.
    #[tokio::test]
    async fn a_redeclared_repository_of_a_turned_off_profile_is_probed() {
        let root = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(root.path().join(".m2")).expect("mkdir");
        std::fs::write(
            root.path().join(".m2/settings.xml"),
            "<settings><profiles><profile><id>corp</id><repositories><repository>\
             <id>corp-dep</id><url>https://corp.example/maven2</url></repository>\
             </repositories></profile></profiles>\
             <activeProfiles><activeProfile>corp</activeProfile></activeProfiles></settings>",
        )
        .expect("write settings.xml");
        std::fs::create_dir_all(root.path().join(".mvn")).expect("mkdir");
        std::fs::write(root.path().join(".mvn/maven.config"), "-P!corp\n").expect("write");
        std::fs::write(
            root.path().join("pom.xml"),
            pom(
                "app",
                &pom_repository("corp-dep", "https://corp.example/maven2"),
                "",
            ),
        )
        .expect("write pom.xml");
        let config = config_in(root.path(), "raeva.toml", "");
        let (client, _cache) = super::build_probe_client(&config)
            .await
            .expect("probe client");
        let (declared, replaced) = super::project_repositories(&config, &client)
            .unwrap_or_else(|row| panic!("{}", row.details));
        assert!(replaced.is_empty(), "{replaced:?}");
        assert!(declared.is_empty());
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
    fn credential_source_reports_none_for_a_server_whose_password_was_dropped() {
        let mut dropped = AuthConfig::new(Some("corp"));
        dropped.password_dropped = true;
        let mut default = AuthConfig::new(None);
        default.token = Some(secrecy::SecretString::from("default-token".to_string()));
        let mut project = AuthConfig::new(Some("corp"));
        project.token = Some(secrecy::SecretString::from("corp-token".to_string()));
        let corp = repository(Some("corp"), "https://repo.example/maven2/");
        let auth = vec![default.clone(), dropped.clone()];
        assert_eq!(credential_source(&auth, &corp, false), None);
        let auth = vec![project, default, dropped];
        assert_eq!(
            credential_source(&auth, &corp, false),
            Some(CredentialSource::ConfigId("corp".to_string()))
        );
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
