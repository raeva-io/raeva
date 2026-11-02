use rv_config::redact_url;
use rv_maven_model::PomError;
use rv_maven_types::is_snapshot_version;
use rv_repo::{CredentialFile, RepoError, SentCredential};
use rv_resolver::{CredentialTarget, DroppedRepo, RepoSearchStatus, RepoStatus, ResolveError};
use rv_store::metadata_cache::CacheError;
use rv_store::{DbFailure, StoreError};
use std::fmt::Write;

use super::{ErrorClass, HintEnv};

/// How many failures an error lists one per line, after the cause; a dead
/// repository fails every file, and "... and N more" stands for the rest.
pub(crate) const LISTED_FAILURES: usize = 10;

/// Append `heading` and up to [`LISTED_FAILURES`] of `lines`, indented.
pub(crate) fn list_failures(out: &mut String, heading: &str, lines: &[String]) {
    let _ = writeln!(out, "\n  {heading}:");
    for line in lines.iter().take(LISTED_FAILURES) {
        let _ = writeln!(out, "    {line}");
    }
    if let Some(more) = lines.len().checked_sub(LISTED_FAILURES)
        && more > 0
    {
        let _ = writeln!(out, "    ... and {more} more");
    }
}

/// An error message and the suggestions that follow it.
///
/// `message` ends with a newline when it spans lines. A hint is the text of
/// one suggestion; a multi-line hint carries its own indentation for the
/// terminal.
#[derive(Debug, Default)]
pub(crate) struct Rendered {
    pub(crate) message: String,
    pub(crate) hints: Vec<String>,
}

impl Rendered {
    pub(crate) fn plain(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            hints: Vec::new(),
        }
    }

    fn hint(&mut self, hint: impl Into<String>) {
        self.hints.push(hint.into());
    }

    fn doctor_hint(&mut self) {
        self.hint("Run 'raeva doctor' to diagnose repository connectivity");
    }

    fn system_path_hints(&mut self) {
        self.hint(
            "Set <systemPath> to an absolute path inside the project, such as \
             ${project.basedir}/lib/name.jar; raeva refuses a path outside it",
        );
        self.hint(
            "Or deploy the jar to a repository and depend on it without system scope, which \
             is not portable",
        );
    }

    #[cfg(test)]
    pub(crate) fn human(&self) -> String {
        join_hints(&self.message, &self.hints)
    }
}

pub(crate) fn join_hints(message: &str, hints: &[String]) -> String {
    let mut out = message.to_string();
    if hints.is_empty() {
        return out;
    }
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str("\n  Suggestions:\n");
    for hint in hints {
        out.push_str("    - ");
        out.push_str(hint);
        out.push('\n');
    }
    out
}

pub(crate) fn render_multiple_artifact_errors(
    first: &ResolveError,
    rest: &[ResolveError],
    env: &HintEnv,
) -> Rendered {
    let first = super::diagnose::diagnose_resolve(first, env);
    let mut hints = first.hints;
    for err in rest.iter().take(LISTED_FAILURES) {
        for hint in super::diagnose::diagnose_resolve(err, env).hints {
            if !hints.contains(&hint) {
                hints.push(hint);
            }
        }
    }
    let mut out = format!(
        "{} artifact fetch error(s); the first:\n\n{}\n",
        1 + rest.len(),
        first.message.trim_end()
    );
    let lines: Vec<String> = (rest.iter())
        .map(|err| match err {
            ResolveError::Repo {
                coord: Some(coord),
                source,
                ..
            } => format!("{coord}: {source}"),
            other => other.to_string(),
        })
        .map(|line| crate::output::inline_text(&line).into_owned())
        .collect();
    list_failures(&mut out, "Also failed", &lines);
    Rendered {
        message: out,
        hints,
    }
}

pub(crate) fn render_repo_error(
    err: &RepoError,
    searched: Option<&[RepoSearchStatus]>,
    env: &HintEnv,
) -> Rendered {
    let class = ErrorClass::of(err);
    if matches!(class, ErrorClass::Auth | ErrorClass::ProxyAuth) {
        return render_auth_error(err, searched, env);
    }
    // A TLS failure counts even when it is not retried, so the error still
    // names its cause and where the trust roots come from.
    if err.is_transient() || err.is_unreachable() || err.tls_cause().is_some() {
        return render_network_error(err, searched, env);
    }
    match err {
        RepoError::InvalidMetadata(_) => return render_invalid_metadata(err, searched),
        RepoError::Store(store) => return render_store_error(store, env),
        RepoError::Cache(cache) => return render_metadata_cache_error(cache, env),
        _ => {}
    }

    if let Some(code @ 500..=599) = err.status_code() {
        let mut out = Rendered::plain(format!("Repository error: {err}\n"));
        append_searched_section(&mut out.message, searched);
        out.hint(format!(
            "The repository failed with HTTP {code}, a fault on its side: run the command \
             again later, and if it persists, tell the repository's operator"
        ));
        out.doctor_hint();
        return out;
    }
    let unpinned = matches!(err, RepoError::UnpinnedLockRow(_));
    let mut out = Rendered::plain(match err {
        // Its text says "invalid configuration", which may name a proxy.
        RepoError::Config(_) => format!("{err}\n"),
        RepoError::UnpinnedLockRow(_) => format!("Lockfile error: {err}\n"),
        _ => format!("Repository error: {err}\n"),
    });
    append_searched_section(&mut out.message, searched);
    if unpinned {
        out.hint(
            "Run 'raeva sync --update' to resolve again and write a lock that pins every artifact",
        );
    }
    if class == ErrorClass::Offline {
        out.hint(
            "--offline reads only what raeva already downloaded; run 'raeva sync' without \
             --offline once to download it",
        );
    }
    if class == ErrorClass::Integrity(rv_repo::IntegritySource::Sidecar) {
        out.message.push_str(
            "\n  The repository served bytes that do not match the checksum it publishes \
             for them.\n",
        );
        out.hint(
            "Run the command again later; an interrupted upload or a proxy that rewrites \
             responses can cause this",
        );
        out.hint("If it persists, report it to the repository's operator");
    }
    out
}

/// The metadata cache, without the SQLite error text behind it.
fn render_metadata_cache_error(err: &CacheError, env: &HintEnv) -> Rendered {
    if err.is_disk_full() {
        return Rendered::plain(format!(
            "repository metadata cache error: disk full; check available space on the volume \
             of {}",
            env.metadata_cache_location()
        ));
    }
    if err.db_failure() == Some(DbFailure::SharedMemory) {
        return Rendered::plain(format!(
            "repository metadata cache error: {}",
            shared_memory_failure(&env.metadata_cache_location())
        ));
    }
    if let CacheError::Setup(inner) = err
        && let rv_store::StoreError::NewerDatabase { path, .. } = &**inner
    {
        let mut out = Rendered::plain(format!("repository metadata cache error: {inner}"));
        out.hint(format!(
            "Run the newer raeva, or delete {} and its -wal and -shm files while no raeva runs: \
             it is a cache, and this raeva starts a new one",
            path.display()
        ));
        return out;
    }
    let io;
    let what = match err {
        CacheError::Db { ctx, .. } => ctx.as_str(),
        CacheError::Pool(_) => "no connection available",
        CacheError::Io(err) => {
            io = err.to_string();
            io.as_str()
        }
        _ => "database error",
    };
    Rendered::plain(format!(
        "repository metadata cache error: {what}; run the command again; if the problem \
         persists, delete {}",
        env.metadata_cache_location()
    ))
}

pub(crate) fn render_pom_error(err: &PomError) -> Rendered {
    let mut out = Rendered::default();
    match err {
        PomError::ParentNotFound(group, artifact, version) => {
            out.message = format!(
                "Parent POM not found: {group}:{artifact}:{version}\n\n  This parent POM could \
                 not be resolved.\n"
            );
            if is_snapshot_version(version) {
                out.hint("SNAPSHOT parents require a repository with snapshots = true");
            }
            out.hint("If the parent is internal, add its repository to raeva.toml");
            out.hint(
                "A local <relativePath> parent is read only inside the project directory, or \
                 one level above a single module; run raeva from a directory that contains it",
            );
        }
        // `raeva doctor` cannot diagnose a missing or relative `<systemPath>`.
        PomError::InvalidSystemPath(msg) => {
            let _ = writeln!(out.message, "Local POM error: {msg}");
            out.system_path_hints();
        }
        _ if err.is_malformed_xml() || matches!(err, PomError::UnparseablePom { .. }) => {
            out.message = format!(
                "Invalid POM metadata: {err}\n\n  The POM is not well-formed XML, and Maven \
                 rejects it too.\n"
            );
            out.hint("Verify the repository is serving a valid POM (not HTML or an error page)");
            out.doctor_hint();
        }
        _ => {
            out.message = format!(
                "Invalid POM metadata: {err}\n\n  The POM was read, but its content is not a \
                 model raeva accepts.\n"
            );
            out.doctor_hint();
        }
    }
    out
}

pub(crate) fn render_local_pom_error(path: &str, err: &rv_maven_model::PomError) -> Rendered {
    use rv_maven_model::PomError;
    let mut out = Rendered::plain(format!("Invalid pom.xml: {err}\n\n  File: {path}\n"));
    match err {
        PomError::InvalidSystemPath(_) => out.system_path_hints(),
        _ if err.is_malformed_xml() || matches!(err, PomError::Deserialize(_)) => {
            out.hint("Check for XML syntax errors (unclosed tags, unescaped characters)");
            out.hint("Verify the file is valid XML by opening it in a browser or XML validator");
        }
        _ => {}
    }
    out.hint("Run 'mvn validate' to check POM validity");
    out
}

pub(crate) fn render_reqwest_error(err: &reqwest::Error) -> Rendered {
    // `reqwest::Error::Display` appends " for url (<url>)" which may contain
    // query-string tokens (e.g. `?token=abc`). Strip the raw URL suffix from
    // the Display string and re-attach a redacted form so the host is still
    // visible for debugging while credentials stay out of error output.
    let raw = err.to_string();
    let base_msg = if let Some(pos) = raw.rfind(" for url (") {
        raw[..pos].to_string()
    } else {
        raw
    };
    let url_suffix = err
        .url()
        .map(|u| format!(" (url: {})", redact_url(u.as_str())))
        .unwrap_or_default();
    let cause = rv_http::transient::transport_detail(err)
        .map(|cause| format!(": {cause}"))
        .unwrap_or_default();
    let mut out = Rendered::plain(format!("HTTP request error: {base_msg}{cause}{url_suffix}"));
    if let Some(tls) = rv_http::tls_cause(err) {
        let _ = write!(out.message, "\nTLS: {}", rv_http::describe_tls_failure(tls));
    }
    if err.is_timeout() || err.is_connect() {
        out.hint("Run 'raeva doctor' to diagnose network or TLS issues");
    }
    out
}

pub(crate) fn render_vuln_error(err: &rv_vuln::VulnError) -> Rendered {
    match err {
        rv_vuln::VulnError::Http(source) => render_reqwest_error(source),
        _ => Rendered::plain(err.to_string()),
    }
}

/// The records OSV named but did not serve, with the purls each was named
/// for, then the first fetch error. Ids and purls passed the OSV id and
/// coordinate checks, so they are safe to print. OSV decides how many
/// there are, so the message names the first few; `failed_records` in the
/// JSON output lists them all. `shared` says whether every failure has the
/// same kind of cause, the one the first failure's error shows.
pub(crate) fn render_unfetched_records(
    failures: &[rv_vuln::FailedFetch],
    shared: bool,
) -> Rendered {
    const RECORDS_SHOWN: usize = 10;
    const PURLS_SHOWN: usize = 3;
    let more = |listed: &mut String, total: usize, shown: usize| {
        if total > shown {
            listed.push_str(&format!(" and {} more", total - shown));
        }
    };
    let mut records = failures
        .iter()
        .take(RECORDS_SHOWN)
        .map(|failed| {
            let mut purls = failed
                .purls
                .iter()
                .take(PURLS_SHOWN)
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(", ");
            more(&mut purls, failed.purls.len(), PURLS_SHOWN);
            format!("{} ({purls})", failed.id)
        })
        .collect::<Vec<_>>()
        .join(", ");
    more(&mut records, failures.len(), RECORDS_SHOWN);
    let mut out = match failures.first() {
        Some(first) => {
            let mut cause = render_vuln_error(&first.error);
            cause.message = if shared {
                format!("{records}; {}", cause.message)
            } else {
                format!(
                    "{records}; they failed for different reasons, the first: {}",
                    cause.message
                )
            };
            cause
        }
        None => Rendered::plain(records),
    };
    out.hint("Run the scan again: until every record is fetched, the findings are incomplete");
    out
}

/// Generate a short, unique repository ID for a `[[repositories]]` entry.
fn suggested_repo_id(url: &str, used: &mut Vec<String>) -> String {
    let parsed = url::Url::parse(url).ok();
    let host = parsed
        .as_ref()
        .and_then(|u| u.host_str())
        .unwrap_or("extra");
    let base = match host {
        "repo1.maven.org" => "central".to_string(),
        _ => {
            let last = parsed
                .as_ref()
                .and_then(|u| u.path_segments())
                .and_then(|mut segments| segments.rfind(|s| !s.is_empty()))
                .unwrap_or("");
            let label = host.split('.').next().unwrap_or(host);
            format!("{label}-{last}")
        }
    };
    let base = base.replace(|c: char| !(c.is_ascii_alphanumeric() || c == '-'), "-");
    let mut id = base.clone();
    let mut n = 2;
    while used.contains(&id) {
        id = format!("{base}-{n}");
        n += 1;
    }
    used.push(id.clone());
    id
}

/// Show how to enable ignored transitive repositories that could serve the
/// artifact, and name the plain-HTTP ones the HTTP blocker refused.
///
/// `[[repositories]]` adds to the defaults, so the snippet lists only the
/// ignored repositories. Only configured repositories may issue cross-origin
/// redirects. The `[security]` allowlist permits transitive declarations, but
/// does not grant redirect authority.
fn append_dropped_repo_hint(out: &mut String, dropped: &[DroppedRepo]) {
    let (blocked, ignored): (Vec<&DroppedRepo>, Vec<&DroppedRepo>) =
        dropped.iter().partition(|repo| repo.http_blocked);
    if !blocked.is_empty() {
        out.push_str(
            "\n  Blocked plain-HTTP repositories, which Maven's default HTTP blocker refuses too:\n",
        );
        for repo in &blocked {
            let _ = writeln!(
                out,
                "    - {} (declared by {})",
                redact_url(&repo.url),
                repo.declared_by
            );
        }
        out.push_str(
            "\n  To allow one, mirror it, or declare its URL in [[repositories]] in raeva.toml,\n  \
             config.toml or settings.xml.\n",
        );
    }
    if ignored.is_empty() {
        return;
    }
    out.push_str(
        "\n  Ignored transitive repositories: raeva ignores dependency POM repositories by default.\n  \
         Maven would search these for this artifact:\n",
    );
    let mut urls: Vec<&str> = Vec::new();
    for repo in ignored {
        let _ = writeln!(
            out,
            "    - {} (declared by {})",
            redact_url(&repo.url),
            repo.declared_by
        );
        if !urls.contains(&repo.url.as_str()) {
            urls.push(&repo.url);
        }
    }
    out.push_str(
        "\n  To use one, add it to raeva.toml. [[repositories]] adds to Maven Central and the\n  \
         repositories already searched:\n",
    );
    let mut used_ids: Vec<String> = Vec::new();
    for url in urls {
        let redacted = redact_url(url);
        let _ = write!(
            out,
            "\n      [[repositories]]\n      id = \"{}\"\n      url = \"{redacted}\"\n",
            suggested_repo_id(url, &mut used_ids)
        );
    }
    out.push_str(
        "\n  A settings.xml profile <repositories> also works, or add the URL to [security]\n  \
         transitive_repository_allowlist in the user config.toml. A repository that redirects\n  \
         downloads to another host still needs a [[repositories]] entry.\n",
    );
}

pub(crate) fn render_dependency_not_found(
    coord: &str,
    searched: &[RepoSearchStatus],
    dropped_repos: &[DroppedRepo],
    classifier_like: Option<&str>,
) -> Rendered {
    let mut out = Rendered::default();
    let message = &mut out.message;
    let _ = writeln!(message, "Dependency not found: {coord}");
    if searched.is_empty() {
        message.push_str("\n  This artifact was not found in any configured repository.\n");
    }
    append_searched_section(message, Some(searched));
    append_dropped_repo_hint(message, dropped_repos);
    let classifier = coord.rsplit(':').next().unwrap_or_default();
    if let Some((like, bare)) = classifier_like.and_then(|bare| {
        let like = classifier.strip_prefix(bare)?.strip_prefix('-')?;
        Some((like, bare))
    }) {
        let _ = write!(
            message,
            "\n  This classifier is what os-maven-plugin makes ${{os.detected.classifier}} on this\n  \
             machine: the build's os.detection.classifierWithLikes lists {like}, and this Linux\n  \
             release is like it. Maven 3.9 resolves the same classifier here.\n"
        );
        out.hint(format!(
            "If the dependency's classifier is ${{os.detected.classifier}}, set\n      \
             -Dos.detected.classifier={bare} in .mvn/maven.config or on the command line:\n      \
             raeva sync -Dos.detected.classifier={bare}"
        ));
    }
    out.hint("Check the group, artifact and version, and that this version is published");
    let configured = searched.iter().any(|entry| {
        let host = url::Url::parse(&entry.repo_url).ok();
        let host = host
            .as_ref()
            .and_then(url::Url::host_str)
            .unwrap_or_default();
        !matches!(host, "repo1.maven.org" | "repo.maven.apache.org")
    });
    let mirrors: Option<std::collections::BTreeSet<String>> = (searched.iter())
        .map(|entry| entry.served_by.as_deref().map(redact_url))
        .collect();
    if configured {
        out.hint(
            "Check the URLs of the repositories searched, including the path (such as an \
             organization name), and that their credentials can read the artifact",
        );
    } else if let Some(mirrors) = mirrors.filter(|mirrors| !mirrors.is_empty()) {
        let (noun, through) = match mirrors.len() {
            1 => ("mirror", "it too if the mirror's"),
            _ => ("mirrors", "one of them too if its"),
        };
        out.hint(format!(
            "Every request went through the {noun} {}, so the artifact must be available \
             there; a repository you add goes through {through} mirrorOf matches it",
            crate::commands::util::join_and(mirrors)
        ));
    } else {
        out.hint(
            "If the artifact is in a private repository, add that repository to \
             [[repositories]] in raeva.toml or to settings.xml",
        );
    }
    out.doctor_hint();
    out
}

pub(crate) fn render_no_repositories() -> Rendered {
    let mut out = Rendered::plain(
        "No repositories configured\n\n  Dependency resolution requires at least one repository.\n",
    );
    out.hint(
        "Add a repository to raeva.toml:\n\n      [[repositories]]\n      id = \"central\"\n      \
         url = \"https://repo1.maven.org/maven2/\"\n",
    );
    out.hint("Run 'raeva doctor' to verify configuration");
    out
}

pub(crate) fn render_version_conflict(coord: &str, requested: &str, selected: &str) -> Rendered {
    let mut out = Rendered::plain(format!(
        "Version conflict: {coord}\n\n  Requested: {requested}\n  Selected: {selected}\n"
    ));
    out.hint("Pin the version in pom.xml, with <dependencyManagement> or a direct dependency");
    out.hint("Run 'raeva tree' to locate conflicting requests");
    out
}

fn render_auth_error(
    err: &RepoError,
    searched: Option<&[RepoSearchStatus]>,
    env: &HintEnv,
) -> Rendered {
    let mut out = Rendered::default();
    let code = err.status_code();
    if !matches!(code, Some(401 | 403)) {
        // Proxy refusals and incomplete credential entries explain themselves.
        let _ = writeln!(out.message, "Authentication failed: {err}");
        append_searched_section(&mut out.message, searched);
        if err.class() == rv_repo::ErrorClass::ProxyAuth {
            if !env.env_proxies.is_empty() {
                out.hint(format!(
                    "The proxy is {}; give it as http://user:password@host:port, with special \
                     characters percent-encoded",
                    env.env_proxies.join(" and ")
                ));
            } else if !env.file_proxies.is_empty() {
                out.hint(format!(
                    "The proxy is {}, from config.toml or settings.xml; give its credentials in \
                     that entry, since HTTPS_PROXY and HTTP_PROXY are not read while a file \
                     names a proxy",
                    env.file_proxies.join(" and ")
                ));
            }
        }
        out.doctor_hint();
        return out;
    }

    let refused = refused_repositories(searched.unwrap_or_default());
    let all_sent = !refused.is_empty() && refused.iter().all(|(target, _)| target.sent.is_some());
    let message = &mut out.message;
    let _ = writeln!(
        message,
        "{}",
        if all_sent {
            "The repository refused the credentials raeva sent"
        } else {
            "Authentication required for repository access"
        }
    );
    if let Some(code) = code {
        let _ = writeln!(message, "\n  The repository returned HTTP {code}.");
    }
    append_searched_section(message, searched);

    if !refused.is_empty() {
        message.push_str("\n  Refused by:\n");
        for (target, code) in &refused {
            let reason = match &target.sent {
                None => "no credentials were sent".to_string(),
                Some(sent) => {
                    let outcome = if *code == 403 {
                        "were sent but do not grant access"
                    } else {
                        "were sent but rejected"
                    };
                    let mut reason = format!(
                        "{} from {} {outcome}",
                        credential_label(sent.id.as_deref()),
                        credential_file(sent.file, &env.settings_location())
                    );
                    if let Some(note) = unset_variables_note(&sent.unset_variables) {
                        let _ = write!(reason, "; {note}");
                    }
                    reason
                }
            };
            let name = target
                .id
                .as_deref()
                .map(|id| format!("'{}'", crate::output::inline_text(id)))
                .unwrap_or_else(|| "repository without an id".to_string());
            let _ = writeln!(
                message,
                "    - {name} at {} (HTTP {code}: {reason})",
                redact_url(&target.url)
            );
        }
    }

    let mut sent_hints: Vec<String> = Vec::new();
    for (target, code) in &refused {
        let Some(sent) = &target.sent else {
            continue;
        };
        let hint = sent_credential_hint(sent, *code, env);
        if !sent_hints.contains(&hint) {
            sent_hints.push(hint);
        }
    }
    for hint in sent_hints {
        out.hint(hint);
    }

    let unsent: Vec<&CredentialTarget> = refused
        .iter()
        .map(|(target, _)| *target)
        .filter(|target| target.sent.is_none())
        .collect();
    let mut ids: Vec<&str> = Vec::new();
    for id in unsent.iter().filter_map(|target| target.id.as_deref()) {
        if !ids.contains(&id) {
            ids.push(id);
        }
    }
    if refused.is_empty() {
        ids.push("repository-id");
    }

    if !ids.is_empty() {
        let mut server = format!(
            "Add a <server> entry to {}. On CI, read the values from\n      environment \
             variables:\n",
            env.settings_location()
        );
        for id in &ids {
            let env = env_var_prefix(id);
            let _ = write!(
                server,
                "\n      <server>\n        <id>{}</id>\n        \
                 <username>${{env.{env}_USER}}</username>\n        \
                 <password>${{env.{env}_TOKEN}}</password>\n      </server>\n",
                // Repository ids can come from POMs; escape before the
                // terminal, including line breaks inside this one-line snippet.
                crate::output::inline_text(id)
                    .replace('&', "&amp;")
                    .replace('<', "&lt;")
                    .replace('>', "&gt;")
            );
        }
        out.hint(server);
        let mut auth = String::from(
            "Or add an [[auth]] entry to your user config file. Keep credentials out \
             of the\n      project raeva.toml, which is usually committed:\n",
        );
        let _ = writeln!(auth, "\n      # {}", env.user_config_location());
        for (index, id) in ids.iter().enumerate() {
            if index > 0 {
                auth.push('\n');
            }
            let _ = writeln!(
                auth,
                "      [[auth]]\n      id = {}\n      username = \"your-username\"\n      \
                 password = \"your-password\"",
                toml_string(id)
            );
        }
        auth.push_str(
            "\n      A registry token that stands in for a password goes in password; use\n      \
             token = \"...\" only for HTTP Bearer authentication.\n",
        );
        out.hint(auth);
    } else if !unsent.is_empty() {
        out.hint(format!(
            "Give the repository an id to configure its credentials in {} or the user \
             config.toml",
            env.settings_location()
        ));
    }
    out.doctor_hint();
    out
}

/// What to check about a credential a repository refused. Names its source,
/// never its value.
fn sent_credential_hint(sent: &SentCredential, code: u16, env: &HintEnv) -> String {
    let label = credential_label(sent.id.as_deref());
    let file = credential_file(sent.file, &env.settings_location());
    if !sent.unset_variables.is_empty() {
        let names: Vec<String> = sent
            .unset_variables
            .iter()
            .map(|name| crate::output::inline_text(name).into_owned())
            .collect();
        let it = if names.len() == 1 { "it" } else { "them" };
        return format!(
            "Set {} in the environment; the {label} in {file} read {it}",
            names.join(" and ")
        );
    }
    if code == 403 {
        format!(
            "Check that the {label} in {file} grant read access to this repository: the \
             token's scope or organization may not cover it"
        )
    } else {
        format!(
            "Check the {label} in {file}: the username or token may be wrong, or the \
             token expired or was revoked"
        )
    }
}

/// `credentials for id 'x'`, or `default credentials` for an entry
/// without an id.
pub(crate) fn credential_label(id: Option<&str>) -> String {
    match id {
        Some(id) => format!("credentials for id '{}'", crate::output::inline_text(id)),
        None => "default credentials".to_string(),
    }
}

/// Where a credential came from; `settings` is the settings file's location.
pub(crate) fn credential_file(file: CredentialFile, settings: &str) -> String {
    match file {
        CredentialFile::Project => "the project raeva.toml".to_string(),
        CredentialFile::User => "the user config.toml".to_string(),
        CredentialFile::Settings => settings.to_string(),
    }
}

/// Why a settings.xml credential that names unset variables cannot work,
/// or `None` when it names none.
pub(crate) fn unset_variables_note(names: &[String]) -> Option<String> {
    if names.is_empty() {
        return None;
    }
    // The names come from settings.xml, so the note shows a few, each cut.
    const SHOWN: usize = 3;
    let verb = if names.len() == 1 { "is" } else { "are" };
    let more = names.len().saturating_sub(SHOWN);
    let mut shown: Vec<String> = names
        .iter()
        .take(SHOWN)
        .map(|name| rv_maven_types::bounded(name).to_string())
        .collect();
    let mut references: Vec<String> = shown
        .iter()
        .map(|name| format!("${{env.{name}}}"))
        .collect();
    if more > 0 {
        shown.push(format!("{more} more"));
        references.push("the others".to_string());
    }
    Some(format!(
        "{} {verb} not set, so the repository received the literal text {}",
        shown.join(" and "),
        references.join(" and ")
    ))
}

/// Each repository that answered 401 or 403, once, with the status it gave.
fn refused_repositories(searched: &[RepoSearchStatus]) -> Vec<(&CredentialTarget, u16)> {
    let mut refused: Vec<(&CredentialTarget, u16)> = Vec::new();
    for entry in searched {
        let (Some(target), RepoStatus::Http(code)) = (&entry.refused_by, &entry.status) else {
            continue;
        };
        if !refused.iter().any(|(known, _)| *known == target) {
            refused.push((target, *code));
        }
    }
    refused
}

fn toml_string(value: &str) -> String {
    let mut out = String::from("\"");
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04X}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// `corp-releases` becomes `CORP_RELEASES`, for `${env.CORP_RELEASES_USER}`.
fn env_var_prefix(id: &str) -> String {
    let name = id
        .to_ascii_uppercase()
        .replace(|c: char| !c.is_ascii_alphanumeric(), "_");
    if name.starts_with(|c: char| c.is_ascii_alphabetic()) {
        name
    } else {
        format!("REPO_{name}")
    }
}

fn render_network_error(
    err: &RepoError,
    searched: Option<&[RepoSearchStatus]>,
    env: &HintEnv,
) -> Rendered {
    let mut out = Rendered::plain(format!(
        "Network error while accessing repositories\n\n  {err}\n"
    ));
    let tls = err.tls_cause();
    if let Some(tls) = tls {
        let _ = writeln!(out.message, "  TLS: {}", rv_http::describe_tls_failure(tls));
    }
    append_searched_section(&mut out.message, searched);
    if tls.is_some() {
        out.hint(match rv_http::trust_roots() {
            rv_http::TrustRoots::Environment { .. } => {
                "If the repository uses a private CA, add it to SSL_CERT_FILE or \
                 SSL_CERT_DIR, which replace the OS trust store"
            }
            _ => "If the repository uses a private CA, install it into your OS trust store",
        });
    }
    if let RepoError::HttpStatus {
        status,
        url,
        retry_after,
    } = err.cause()
        && err.is_transient()
    {
        let host = url::Url::parse(url)
            .ok()
            .and_then(|url| url.host_str().map(str::to_string))
            .unwrap_or_else(|| url.clone());
        let _ = writeln!(
            out.message,
            "\n  {host} answered {status}, as a busy or rate-limited server does. When \
             resolving, raeva does not fall back to another repository after such an \
             answer, on purpose, so raeva.lock does not depend on which repository answered."
        );
        if let Some(wait) = retry_after.filter(|wait| *wait > rv_http::retry::MAX_BUSY_WAIT) {
            let _ = writeln!(
                out.message,
                "  It asked for {} s before the next request, longer than raeva waits ({} s), \
                 so raeva did not ask again.",
                wait.as_secs(),
                rv_http::retry::MAX_BUSY_WAIT.as_secs()
            );
        }
        out.hint("Run the command again later");
        out.hint(format!(
            "Or route {host} through a mirror: [[mirrors]] in config.toml or <mirror> in \
             settings.xml"
        ));
        out.doctor_hint();
        return out;
    }
    if err.is_transient() {
        out.hint(
            "Run the command again later: when resolving, raeva does not fall back to \
             another repository after a failure like this, on purpose, so raeva.lock does \
             not depend on which repository answered",
        );
    }
    if !env.file_proxies.is_empty() {
        out.hint(format!(
            "raeva connects through the proxy {}, from config.toml or settings.xml; check that \
             it answers, or list the hosts to reach directly in its non_proxy_hosts \
             (<nonProxyHosts> in settings.xml)",
            env.file_proxies.join(" and ")
        ));
    } else if env.env_proxies.is_empty() {
        out.hint("Check your network connection and proxy settings");
        out.hint(
            "If you are behind a proxy, set HTTPS_PROXY and HTTP_PROXY (NO_PROXY for hosts \
             to reach directly), or configure one in config.toml or settings.xml",
        );
    } else {
        out.hint(format!(
            "raeva connects through the proxy {}; check that it answers, or list the hosts \
             to reach directly in NO_PROXY",
            env.env_proxies.join(" and ")
        ));
    }
    out.doctor_hint();
    out
}

fn render_invalid_metadata(err: &RepoError, searched: Option<&[RepoSearchStatus]>) -> Rendered {
    let mut out = Rendered::plain(format!(
        "Invalid repository metadata: {err}\n\n  The POM or metadata could not be parsed.\n"
    ));
    append_searched_section(&mut out.message, searched);
    out.hint("Verify the repository is serving valid metadata (not HTML or an error page)");
    out.hint("Try 'raeva sync --update' to refetch metadata");
    out.doctor_hint();
    out
}

fn append_searched_section(out: &mut String, searched: Option<&[RepoSearchStatus]>) {
    let Some(searched) = searched else {
        return;
    };
    if searched.is_empty() {
        return;
    }

    out.push_str("\n  Searched:\n");
    for entry in searched {
        // Redact credentials from the repository URL before printing. A user
        // may have configured `https://user:pass@repo.example.com/` in raeva.toml;
        // that would appear verbatim in `ArtifactNotFound` and similar errors
        // without this guard.
        let mirror = entry
            .served_by
            .as_deref()
            .map(|mirror| format!(" through mirror {}", redact_url(mirror)))
            .unwrap_or_default();
        let url = redact_url(&entry.repo_url);
        let _ = writeln!(out, "    - {url}{mirror} ({})", entry.status);
    }
}

/// Produce a user-facing message for artifact store errors.
///
/// Avoids leaking rusqlite internals such as
/// `SqliteFailure(Error { code: DiskFull, extended_code: … }, …)`.
/// SQLite could not grow a database's `-shm` file: a full volume, most
/// often, though an I/O error does the same.
fn shared_memory_failure(database: &str) -> String {
    format!(
        "could not grow the shared-memory file of {database}, most often because its volume is \
         full; check available space there"
    )
}

pub(crate) fn render_store_error(err: &StoreError, env: &HintEnv) -> Rendered {
    use std::io::ErrorKind;
    const DISK_FULL: &str = "disk full; check available space on the store volume";
    let sync = "raeva sync";
    let store = env.store_location();
    let detail = match err {
        // Already actionable (process info, advice on NOT deleting the lock
        // file), with no implementation details.
        StoreError::LockTimeout { .. } => return Rendered::plain(err.to_string()),
        // The store index is not a cache: deleting it loses what the store
        // holds.
        StoreError::NewerDatabase { .. } => {
            let mut out = Rendered::plain(format!("artifact store error: {err}"));
            out.hint("Run the newer raeva, or give this one its own RAEVA_HOME");
            return out;
        }
        StoreError::IoError(io_err) => match io_err.kind() {
            ErrorKind::StorageFull | ErrorKind::QuotaExceeded | ErrorKind::OutOfMemory => {
                DISK_FULL.to_string()
            }
            ErrorKind::PermissionDenied => format!(
                "permission denied accessing the store at {store}; check directory permissions"
            ),
            ErrorKind::NotFound => {
                format!("store file or directory not found; run '{sync}' to initialise the store")
            }
            _ => format!("I/O error: {io_err}"),
        },
        StoreError::DbContext { ctx, .. } => match err.db_failure() {
            Some(DbFailure::DiskFull) => DISK_FULL.to_string(),
            Some(DbFailure::SharedMemory) => {
                shared_memory_failure(&format!("the store index in {store}"))
            }
            Some(DbFailure::CannotOpen) => {
                "cannot open the artifact database; check directory permissions".to_string()
            }
            // A run replaces a damaged index while no other process has it
            // open; the blobs stay.
            Some(DbFailure::Corrupt) => format!(
                "the store index in {store} is damaged; run '{sync}' again once no other raeva \
                 process uses the store, and raeva starts a new index"
            ),
            _ => format!(
                "{}; try running '{sync}' again; if the problem persists, delete {store}",
                ctx.as_str()
            ),
        },
        StoreError::PoolError(detail) => {
            format!("no database connection available ({detail}); try again in a moment")
        }
        StoreError::InvalidBlobId(_) => {
            "internal integrity violation (invalid blob id); please file a bug".to_string()
        }
        StoreError::IntegrityError(msg) => format!("integrity check failed: {msg}"),
        _ => err.to_string(),
    };
    Rendered::plain(format!("artifact store error: {detail}"))
}
#[cfg(test)]
mod tests {
    use super::render_vuln_error;
    use crate::error::HintEnv;

    fn env() -> HintEnv {
        HintEnv::discover()
    }

    fn render_resolve_error(err: &ResolveError) -> String {
        crate::error::diagnose::diagnose_resolve(err, &env()).human()
    }

    use rv_resolver::{RepoSearchStatus, RepoStatus, ResolveError};

    #[tokio::test]
    async fn vulnerability_http_error_redacts_base_url_credentials() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let address = listener.local_addr().expect("test server address");
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept request");
            drop(stream);
        });
        let error = rv_http::client_builder()
            .build()
            .expect("client")
            .get(format!(
                "http://user:secret@{address}/v1/query?token=private"
            ))
            .send()
            .await
            .expect_err("closed connection must fail");
        server.join().expect("test server");

        let rendered = render_vuln_error(&rv_vuln::VulnError::Http(error)).human();
        assert!(!rendered.contains("secret"), "rendered={rendered}");
        assert!(!rendered.contains("private"), "rendered={rendered}");
        assert!(rendered.contains("127.0.0.1"), "rendered={rendered}");
    }

    /// Repository URLs with credentials must not appear verbatim in the
    /// `Searched:` section of `ArtifactNotFound` errors.
    #[test]
    fn artifact_not_found_redacts_repo_url_in_searched_section() {
        let searched = vec![RepoSearchStatus::new(
            "https://user:pass@private.example.com/maven/",
            RepoStatus::Http(404),
        )];
        let err = ResolveError::ArtifactNotFound {
            dropped_repos: Vec::new(),
            coord: "com.example:lib:1.0".to_string(),
            searched,
            classifier_like: None,
        };
        let rendered = render_resolve_error(&err);
        assert!(
            !rendered.contains("pass"),
            "password must not appear in searched section: {rendered}"
        );
        assert!(
            !rendered.contains("user:"),
            "userinfo must not appear in searched section: {rendered}"
        );
        assert!(
            rendered.contains("private.example.com"),
            "host must remain visible: {rendered}"
        );
    }

    fn refused(url: &str, code: u16, id: Option<&str>, served_by: &str) -> RepoSearchStatus {
        let mut status = RepoSearchStatus::new(url, RepoStatus::Http(code));
        status.refused_by = Some(rv_resolver::CredentialTarget {
            id: id.map(str::to_string),
            url: served_by.to_string(),
            sent: None,
        });
        status
    }

    fn auth_failure(code: u16, searched: Vec<RepoSearchStatus>) -> ResolveError {
        ResolveError::Repo {
            coord: Some("io.raeva:lib:1.0".to_string()),
            source: Box::new(rv_repo::RepoError::Unauthorized {
                status: reqwest::StatusCode::from_u16(code).expect("status"),
                url: "https://registry.raeva.io/maven/canary/io/raeva/lib/1.0/lib-1.0.pom"
                    .to_string(),
                sent: None,
            }),
            searched,
        }
    }

    #[test]
    fn unauthorized_names_the_refusing_repository_and_keeps_secrets_out_of_rv_toml() {
        let canary = "https://registry.raeva.io/maven/canary/";
        let err = auth_failure(
            401,
            vec![
                RepoSearchStatus::new("https://repo1.maven.org/maven2/", RepoStatus::Http(404)),
                refused(canary, 401, Some("raeva"), canary),
            ],
        );
        let rendered = render_resolve_error(&err);
        assert!(
            rendered.contains(
                "'raeva' at https://registry.raeva.io/maven/canary/ (HTTP 401: no credentials \
                 were sent)"
            ),
            "{rendered}"
        );
        let server = rendered
            .find("<server>\n        <id>raeva</id>\n        <username>${env.RAEVA_USER}</username>\n        <password>${env.RAEVA_TOKEN}</password>")
            .expect("settings.xml suggestion");
        let user_config = rendered
            .find("[[auth]]\n      id = \"raeva\"\n")
            .expect("user config suggestion");
        assert!(server < user_config, "{rendered}");
        assert!(rendered.contains("~/.m2/settings.xml"), "{rendered}");
        assert!(rendered.contains("config.toml"), "{rendered}");
        assert!(!rendered.contains("id = \"private\""), "{rendered}");
        assert!(
            !rendered.contains("credentials in raeva.toml"),
            "must not suggest secrets in the project raeva.toml: {rendered}"
        );
        assert!(rendered.contains("'raeva doctor'"), "{rendered}");
    }

    #[test]
    fn auth_hint_never_echoes_url_credentials() {
        let url = "https://alice:hunter2@corp.example/maven/?token=topsecret";
        let rendered = render_resolve_error(&auth_failure(
            401,
            vec![refused(url, 401, Some("corp"), url)],
        ));
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(!rendered.contains("topsecret"), "{rendered}");
        assert!(rendered.contains("<id>corp</id>"), "{rendered}");
    }

    #[test]
    fn auth_hint_escapes_hostile_repository_ids() {
        let url = "https://corp.example/maven/";
        let rendered = render_resolve_error(&auth_failure(
            401,
            vec![refused(url, 401, Some("a\u{1b}[2J<b>\""), url)],
        ));
        assert!(!rendered.contains('\u{1b}'), "{rendered}");
        assert!(
            rendered.contains("<id>a\\u{1b}[2J&lt;b&gt;\"</id>"),
            "{rendered}"
        );
        assert!(
            rendered.contains("id = \"a\\u001B[2J<b>\\\"\""),
            "{rendered}"
        );
    }

    #[test]
    fn unset_variable_names_are_escaped_and_cut() {
        let long = format!("A\u{1b}[2J{}", "B".repeat(500));
        let note = super::unset_variables_note(&[long]).unwrap();
        assert!(!note.contains('\u{1b}') && note.len() < 400, "{note}");
        let many: Vec<String> = (0..1000).map(|i| format!("V{i}")).collect();
        let note = super::unset_variables_note(&many).unwrap();
        assert_eq!(
            note,
            "V0 and V1 and V2 and 997 more are not set, so the repository received the \
             literal text ${env.V0} and ${env.V1} and ${env.V2} and the others"
        );
    }
}
