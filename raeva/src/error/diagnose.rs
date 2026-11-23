//! The one place that decides what a [`CliError`] tells the user and which
//! exit status it gives.

use std::path::PathBuf;

use rv_repo::RepoError;
use rv_resolver::ResolveError;

use super::report::{self, Rendered};
use super::{CliError, ErrorClass, ExitStatus};
use crate::commands::export_m2::ExportError;

#[derive(Clone, Debug)]
pub(crate) struct HintEnv {
    pub(crate) store_dir: Option<PathBuf>,
    pub(crate) user_config: Option<PathBuf>,
    pub(crate) metadata_cache: Option<PathBuf>,
    /// The Maven settings file the configuration read.
    pub(crate) settings_file: Option<PathBuf>,
    /// The proxies `HTTPS_PROXY` and `HTTP_PROXY` gave, as `host:port from
    /// VARIABLE`.
    pub(crate) env_proxies: Vec<String>,
    /// The proxies config.toml and settings.xml name, as `host:port`. The
    /// proxy variables are not read while there are any.
    pub(crate) file_proxies: Vec<String>,
    /// Maven 3.10's credential scope, and the ids whose username and
    /// password come from settings.xml, which it binds.
    pub(crate) credential_scope: Option<(rv_config::CredentialScope, Vec<String>)>,
    /// The ids of the settings.xml servers whose encrypted password raeva
    /// could not decrypt, which give no credential.
    pub(crate) dropped_passwords: Vec<String>,
}

impl HintEnv {
    pub(crate) fn from_paths(paths: Option<&rv_config::ResolvedPaths>) -> Self {
        Self {
            store_dir: paths.map(|paths| paths.store_dir.clone()),
            user_config: paths.map(|paths| rv_fs::plain_path(&paths.config_file_path())),
            metadata_cache: paths.map(rv_config::ResolvedPaths::metadata_db_path),
            settings_file: None,
            env_proxies: Vec::new(),
            file_proxies: Vec::new(),
            credential_scope: None,
            dropped_passwords: Vec::new(),
        }
    }

    /// The directories and files `config` names.
    pub(crate) fn for_config(config: &rv_config::Config) -> Self {
        let (env_proxies, file_proxies) = Self::proxy_labels(config);
        Self {
            settings_file: config.settings_path.clone(),
            env_proxies,
            file_proxies,
            credential_scope: (config.credential_scope())
                .map(|scope| (scope.clone(), settings_password_ids(config))),
            dropped_passwords: (config.auth_layers().settings().iter())
                .filter(|entry| entry.password_dropped)
                .filter_map(|entry| entry.id.clone())
                .collect(),
            ..Self::from_paths(Some(&config.paths))
        }
    }

    /// Whether sync keeps the settings.xml username and password of `id`
    /// from `url` in the Maven 3.10 mode, as Maven's credential scope does.
    pub(crate) fn scope_withholds(&self, id: &str, url: &str) -> bool {
        (self.credential_scope.as_ref()).is_some_and(|(scope, ids)| {
            ids.iter().any(|known| known == id) && !scope.sends(id, url)
        })
    }

    /// Whether the settings.xml server `id` gave no credential because its
    /// password could not be decrypted.
    pub(crate) fn password_dropped(&self, id: &str) -> bool {
        self.dropped_passwords.iter().any(|dropped| dropped == id)
    }

    /// The labels of `config`'s proxies, for [`Self::env_proxies`] and
    /// [`Self::file_proxies`].
    fn proxy_labels(config: &rv_config::Config) -> (Vec<String>, Vec<String>) {
        let (mut env, mut files) = (Vec::new(), Vec::new());
        for proxy in config.proxies() {
            // An IPv6 literal bracketed, as in a URL. A host with
            // credentials is refused before any request.
            let host = &proxy.host;
            let label = match host.contains(':') && !host.starts_with('[') {
                true => format!("[{host}]:{}", proxy.port),
                false => format!("{host}:{}", proxy.port),
            };
            match &proxy.environment {
                Some(environment) => env.push(format!("{label} from {}", environment.variable)),
                None if !files.contains(&label) => files.push(label),
                None => {}
            }
        }
        (env, files)
    }

    /// The directories as this process would discover them, for errors
    /// raised before any configuration was loaded.
    pub(crate) fn discover() -> Self {
        Self::from_paths(rv_config::ResolvedPaths::discover().ok().as_ref())
    }

    pub(crate) fn store_location(&self) -> String {
        shown(&self.store_dir, "the raeva store directory")
    }

    pub(crate) fn user_config_location(&self) -> String {
        shown(
            &self.user_config,
            "config.toml in the raeva config directory",
        )
    }

    pub(crate) fn metadata_cache_location(&self) -> String {
        shown(
            &self.metadata_cache,
            "metadata.db in the raeva data directory",
        )
    }

    pub(crate) fn settings_location(&self) -> String {
        shown(&self.settings_file, "~/.m2/settings.xml")
    }
}

fn shown(path: &Option<PathBuf>, unknown: &str) -> String {
    path.as_ref()
        .map_or_else(|| unknown.to_string(), |path| path.display().to_string())
}

/// What a failed command reports: a stable `code` for scripts, the message,
/// the suggestions, and the exit status.
#[derive(Clone, Debug)]
pub(crate) struct Diagnostic {
    pub(crate) status: ExitStatus,
    pub(crate) code: &'static str,
    pub(crate) message: String,
    pub(crate) hints: Vec<String>,
    pub(crate) location: Option<Location>,
}

/// Where a failure happened: the reactor module's POM path, and the
/// `group:artifact:version` of each POM from the module's direct dependency
/// down to the one that declares the failed dependency.
#[derive(Clone, Debug, Default)]
pub(crate) struct Location {
    pub(crate) module: String,
    pub(crate) via: Vec<String>,
}

impl Location {
    fn line(&self) -> Option<String> {
        match (self.module.as_str(), self.via.as_slice()) {
            ("", []) => None,
            (module, []) => Some(format!("  In {module}")),
            ("", via) => Some(format!("  Through {}", via.join(" -> "))),
            (module, via) => Some(format!("  In {module}, through {}", via.join(" -> "))),
        }
    }
}

impl Diagnostic {
    fn new(status: ExitStatus, code: &'static str, rendered: Rendered) -> Self {
        Self {
            status,
            code,
            message: rendered.message,
            hints: rendered.hints,
            location: None,
        }
    }

    fn plain(status: ExitStatus, code: &'static str, message: impl Into<String>) -> Self {
        Self::new(status, code, Rendered::plain(message))
    }

    pub(crate) fn human(&self) -> String {
        report::join_hints(&self.message, &self.hints)
    }
}

impl CliError {
    /// The message, hints and exit status for this error. The exit status
    /// depends on the error that encloses a cause, not only on the
    /// innermost one: a repository refusal under resolution is still an
    /// authentication problem, but a store failure nested in a repository
    /// error is a store failure, not a resolution failure.
    pub(crate) fn diagnose(&self, env: &HintEnv) -> Diagnostic {
        use ExitStatus as S;
        let (status, code) = match self {
            CliError::Resolve(err) => return diagnose_resolve(err, env),
            CliError::Repo(err) => return diagnose_repo(err, None, env),
            CliError::Download { failures, first } => {
                let cause = diagnose_repo(first, None, env);
                let mut message = format!(
                    "failed to download {} artifact(s): {}\n",
                    failures.len(),
                    cause.message.trim_end()
                );
                let failures: Vec<String> = (failures.iter())
                    .map(|line| crate::output::inline_text(line).into_owned())
                    .collect();
                report::list_failures(&mut message, "Failed", &failures);
                return Diagnostic { message, ..cause };
            }
            CliError::Store(err) => {
                return Diagnostic::new(S::Failure, "STORE", report::render_store_error(err, env));
            }
            CliError::Export(err) => return diagnose_export(err, env),
            CliError::Vuln(err) => {
                let (status, code) = vuln_class(err);
                return Diagnostic::new(status, code, report::render_vuln_error(err));
            }
            CliError::VulnRecordsUnfetched { failures } => {
                // One status for all: the shared one, or the service's own
                // failure when the causes differ.
                let mut classes = failures.iter().map(|failed| vuln_class(&failed.error));
                let first = classes
                    .next()
                    .unwrap_or((S::Failure, "VULNERABILITY_SERVICE"));
                let shared = classes.all(|class| class == first);
                let (status, code) = if shared {
                    first
                } else {
                    (S::Failure, "VULNERABILITY_SERVICE")
                };
                let mut rendered = report::render_unfetched_records(failures, shared);
                rendered.message = format!("{self}: {}", rendered.message);
                return Diagnostic::new(status, code, rendered);
            }
            CliError::VulnerabilityScan(cause) => {
                // A scan with no lock to read never started.
                let started = !matches!(
                    **cause,
                    CliError::LockfileMissing { .. }
                        | CliError::LockfileNotAFile { .. }
                        | CliError::LockfileIncompatible { .. }
                        | CliError::LockfileTooNew { .. }
                );
                let cause = cause.diagnose(env);
                return Diagnostic {
                    status: cause.status.of_failed_scan(),
                    message: match started {
                        true => format!("vulnerability scan failed: {}", cause.message),
                        false => cause.message.clone(),
                    },
                    ..cause
                };
            }
            CliError::OfflinePlugins(cause) => {
                let mut cause = cause.diagnose(env);
                if cause.code == "OFFLINE_NOT_CACHED" {
                    cause.hints = vec![format!(
                        "Run '{}' online once, or restore a seed, to make this home ready \
                         offline: a plain 'raeva sync' does not download what the plugin check \
                         reads",
                        crate::output::command_line("sync --frozen")
                    )];
                }
                return cause;
            }
            CliError::Config(_) | CliError::Platform(_) => (S::Config, "CONFIG"),
            CliError::Lock(err) => match err {
                rv_lock::LockError::Io { .. } => (S::Failure, "IO"),
                rv_lock::LockError::UnrecordableOrigin(_) => (S::Config, "REPOSITORY_CONFIG"),
                _ => (S::Config, "LOCKFILE_INVALID"),
            },
            CliError::InvalidProjectInput { .. } => (S::Config, "INVALID_PROJECT_INPUT"),
            CliError::RepositoryOriginAlias { .. } => (S::Config, "REPOSITORY_ORIGIN_ALIAS"),
            CliError::ProjectFileMissing { .. } => {
                let mut rendered = Rendered::plain(self.to_string());
                rendered.hints.push(
                    "Run raeva in the directory of the root pom.xml, or name that directory \
                     with -C <dir>"
                        .to_string(),
                );
                return Diagnostic::new(S::Config, "PROJECT_FILE_MISSING", rendered);
            }
            CliError::LocalRepository { .. } => (S::Config, "LOCAL_REPOSITORY"),
            CliError::LockfileMissing {
                sync_creates,
                reactor,
                ..
            } => {
                let mut rendered = Rendered::plain(self.to_string());
                if *sync_creates && reactor.is_none() {
                    rendered.hints.push(
                        "Run 'raeva sync' to create it and commit raeva.lock; CI checks it with \
                         'raeva sync --frozen'"
                            .to_string(),
                    );
                }
                return Diagnostic::new(S::Config, "LOCKFILE_MISSING", rendered);
            }
            CliError::LockfileNotAFile { .. } => (S::Config, "LOCKFILE_NOT_A_FILE"),
            CliError::LockfileIncompatible { regenerate, .. } => {
                let mut rendered = Rendered::plain(self.to_string());
                rendered.hints.push(
                    match regenerate {
                        Some(true) => "Run 'raeva sync' without --frozen to regenerate it",
                        Some(false) => {
                            "Run 'raeva sync --update' to regenerate it without its pins, which a \
                         plain sync cannot keep, or delete raeva.lock"
                        }
                        None => {
                            "Delete raeva.lock and run 'raeva sync', which cannot read this one to \
                         keep the platforms it names"
                        }
                    }
                    .to_string(),
                );
                return Diagnostic::new(S::Config, "LOCKFILE_INVALID", rendered);
            }
            CliError::LockfileUnreplaced { hint, .. } => {
                let mut rendered = Rendered::plain(self.to_string());
                rendered.hints.push(hint.clone());
                return Diagnostic::new(S::Config, "LOCKFILE_INVALID", rendered);
            }
            CliError::LockfileDefect { .. } => (S::Config, "LOCKFILE_INVALID"),
            CliError::LockfileTooNew { found, .. } => {
                let mut rendered = Rendered::plain(self.to_string());
                rendered.hints.push(format!(
                    "Upgrade raeva to a release that reads schema {found}, here and where CI \
                     installs it"
                ));
                return Diagnostic::new(S::Config, "LOCKFILE_INVALID", rendered);
            }
            CliError::PlatformMissing {
                platform,
                recorded,
                frozen,
            } => {
                let mut rendered = Rendered::plain(self.to_string());
                rendered.hints.push(format!(
                    "Run 'raeva sync --platforms {platform}' to add it; the sync keeps the \
                     platforms raeva.lock records"
                ));
                if *frozen && !recorded.is_empty() {
                    rendered.hints.push(format!(
                        "Or check only the recorded platforms: 'raeva sync --frozen \
                         --platforms {}'",
                        recorded.join(",")
                    ));
                }
                let unknown: Vec<&str> = recorded
                    .iter()
                    .map(String::as_str)
                    .filter(|name| !crate::commands::SUPPORTED_PLATFORMS.contains(name))
                    .collect();
                if !unknown.is_empty() {
                    rendered.hints.push(format!(
                        "No machine checks {}: raeva names platforms {}",
                        unknown.join(", "),
                        crate::commands::SUPPORTED_PLATFORMS.join(", ")
                    ));
                }
                return Diagnostic::new(S::Config, "PLATFORM_MISSING", rendered);
            }
            CliError::OtherPlatformOrigin { .. } => {
                let mut rendered = Rendered::plain(self.to_string());
                rendered.hints.push(
                    "Run 'raeva sync --frozen', or 'raeva sync', without --platforms: it \
                     resolves every platform, through the repositories each one's build declares"
                        .to_string(),
                );
                return Diagnostic::new(S::Config, "OTHER_PLATFORM_ORIGIN", rendered);
            }
            CliError::LockfileMismatch { details, hint } => {
                let mut rendered = Rendered::plain(details.clone());
                rendered.hints.push(
                    hint.clone()
                        .unwrap_or_else(|| "Run 'raeva sync' to update raeva.lock".to_string()),
                );
                return Diagnostic::new(S::LockMismatch, "LOCKFILE_MISMATCH", rendered);
            }
            CliError::LockfileBusy { .. } => (S::Failure, "LOCKFILE_BUSY"),
            CliError::Usage(_) => (S::Usage, "USAGE"),
            CliError::IoWithPath { path, source }
                if source.kind() == std::io::ErrorKind::PermissionDenied =>
            {
                let mut rendered = Rendered::plain(self.to_string());
                rendered.hints.push(format!(
                    "Check the permissions of {} and of its directory",
                    path.display()
                ));
                return Diagnostic::new(S::Failure, "IO", rendered);
            }
            CliError::Io(_) | CliError::IoWithPath { .. } => (S::Failure, "IO"),
            CliError::Sbom(_) => (S::Failure, "SBOM"),
            CliError::Serialization(_) | CliError::Internal(_) => (S::Failure, "INTERNAL"),
            CliError::NoDependencyPath { .. } => (S::Failure, "NOT_FOUND"),
            CliError::DoctorChecksFailed { status, .. } => (*status, "DOCTOR_CHECKS_FAILED"),
            CliError::VulnerabilitiesFound { .. } => (S::Failure, "VULNERABILITIES_FOUND"),
            CliError::Message(_) => (S::Failure, "ERROR"),
        };
        Diagnostic::plain(status, code, self.to_string())
    }
}

/// The status and code of an OSV failure. As for downloads, only what a
/// retry could fix is the network; a 500 or a redirect loop is the
/// service's own.
fn vuln_class(err: &rv_vuln::VulnError) -> (ExitStatus, &'static str) {
    use rv_vuln::VulnError;
    // A proxy's refusal, of the tunnel or of a plain request, as a download
    // classes it.
    let proxy = || {
        (
            ErrorClass::ProxyAuth.exit_status(),
            class_code(ErrorClass::ProxyAuth),
        )
    };
    match err {
        VulnError::Http(source) if rv_http::transient::tunnel_refusal(source).is_some() => proxy(),
        VulnError::HttpStatus { status, .. }
            if *status == reqwest::StatusCode::PROXY_AUTHENTICATION_REQUIRED =>
        {
            proxy()
        }
        VulnError::Http(source)
            if rv_http::tls_cause(source).is_some_and(rv_http::tls_failure_is_permanent) =>
        {
            (ExitStatus::Config, "TLS")
        }
        VulnError::Http(source) if rv_http::transient::transport_is_transient(source) => {
            (ExitStatus::Network, "NETWORK")
        }
        VulnError::RateLimited { .. } | VulnError::Truncated { .. } => {
            (ExitStatus::Network, "NETWORK")
        }
        VulnError::HttpStatus { status, .. }
            if rv_http::transient::status_is_transient(*status) =>
        {
            (ExitStatus::Network, "NETWORK")
        }
        _ => (ExitStatus::Failure, "VULNERABILITY_SERVICE"),
    }
}

fn diagnose_repo(
    err: &RepoError,
    searched: Option<&[rv_resolver::RepoSearchStatus]>,
    env: &HintEnv,
) -> Diagnostic {
    let class = ErrorClass::of(err);
    Diagnostic::new(
        class.exit_status(),
        class_code(class),
        report::render_repo_error(err, searched, env),
    )
}

pub(crate) fn class_code(class: ErrorClass) -> &'static str {
    match class {
        ErrorClass::Auth => "AUTH",
        ErrorClass::ProxyAuth => "PROXY_AUTH",
        ErrorClass::Network => "NETWORK",
        ErrorClass::Tls => "TLS",
        ErrorClass::Config => "REPOSITORY_CONFIG",
        ErrorClass::Integrity(rv_repo::IntegritySource::Sidecar) => "INTEGRITY",
        ErrorClass::Integrity(rv_repo::IntegritySource::LockPin) => "LOCKFILE_MISMATCH",
        ErrorClass::NotFound => "NOT_FOUND",
        ErrorClass::Store => "STORE",
        ErrorClass::Offline => "OFFLINE_NOT_CACHED",
        ErrorClass::Lockfile => "LOCKFILE_INVALID",
        ErrorClass::Internal => "INTERNAL",
        ErrorClass::Other => "REPOSITORY",
    }
}

pub(crate) fn diagnose_resolve(err: &ResolveError, env: &HintEnv) -> Diagnostic {
    use ExitStatus as S;
    // Exhaustive: a new variant needs an explicit decision here.
    match err {
        ResolveError::Repo {
            coord,
            source,
            searched,
        } => {
            let mut diagnostic = diagnose_repo(source, Some(searched), env);
            if let Some(coord) = coord {
                diagnostic.message = format!(
                    "While fetching {}:\n\n{}",
                    crate::output::inline_text(coord),
                    diagnostic.message
                );
            }
            diagnostic
        }
        ResolveError::Store(source) => {
            Diagnostic::new(S::Failure, "STORE", report::render_store_error(source, env))
        }
        ResolveError::FilteredModel { error, searched } => {
            let mut diagnostic = diagnose_resolve(error, env);
            report::append_searched_section(&mut diagnostic.message, Some(searched));
            diagnostic.hints.insert(0, report::FILTERED_HINT.to_string());
            diagnostic
        }
        ResolveError::MultipleArtifactErrors { first, rest } => {
            let first_diagnostic = diagnose_resolve(first, env);
            Diagnostic {
                location: first_diagnostic.location,
                ..Diagnostic::new(
                    first_diagnostic.status,
                    first_diagnostic.code,
                    report::render_multiple_artifact_errors(first, rest, env),
                )
            }
        }
        ResolveError::Plugin {
            plugin,
            searched,
            error,
        } => {
            let mut diagnostic = diagnose_resolve(error, env);
            diagnostic.message = format!(
                "While resolving the {}:\n\n{}",
                crate::output::inline_text(plugin),
                diagnostic.message
            );
            if let ResolveError::Pom(rv_maven_model::PomError::ParentNotFound(..)) = error.cause()
                && !searched.is_empty()
                && !names_filtered_model(error)
            {
                diagnostic.message.push_str(
                    "\n  None of the repositories the plugin pass searched for this plugin has it:\n",
                );
                for url in searched {
                    let url = rv_config::redact_url(url);
                    diagnostic.message.push_str(&format!("    - {url}\n"));
                }
            }
            diagnostic
        }
        ResolveError::Declared { module, via, error } => {
            let mut diagnostic = diagnose_resolve(error, env);
            let location = Location {
                module: module.clone(),
                via: via.clone(),
            };
            if let Some(line) = location.line() {
                // After the line that names the failure; "While fetching x:"
                // only introduces it.
                let message = &diagnostic.message;
                let at = (message.match_indices('\n').map(|(at, _)| at))
                    .find(|&at| {
                        let line = message[..at].rsplit('\n').next().unwrap_or_default();
                        !line.trim().is_empty() && !line.ends_with(':')
                    })
                    .unwrap_or(message.len());
                let (head, rest) = message.split_at(at);
                let rest = rest.trim_start_matches('\n');
                let separator = if rest.is_empty() { "" } else { "\n" };
                diagnostic.message = format!("{head}\n\n{line}\n{separator}{rest}");
            }
            diagnostic.location = Some(location);
            diagnostic
        }
        ResolveError::ArtifactNotFound {
            coord,
            searched,
            dropped_repos,
            classifier_like,
        } => Diagnostic::new(
            S::Resolution,
            "ARTIFACT_NOT_FOUND",
            report::render_dependency_not_found(
                coord,
                searched,
                dropped_repos,
                classifier_like.as_deref(),
            ),
        ),
        ResolveError::NoRepositories => Diagnostic::new(
            S::Config,
            "NO_REPOSITORIES",
            report::render_no_repositories(),
        ),
        ResolveError::VersionConflict {
            coord,
            requested,
            selected,
        } => Diagnostic::new(
            S::Resolution,
            "VERSION_CONFLICT",
            report::render_version_conflict(coord, requested, selected),
        ),
        ResolveError::Pom(source @ rv_maven_model::PomError::SecretCoordinate { .. }) => {
            Diagnostic::plain(S::Config, "INVALID_POM", source.to_string())
        }
        // Maven builds a model raeva cannot lock the same way: a refusal.
        ResolveError::Pom(source) => Diagnostic::new(
            match source {
                rv_maven_model::PomError::Unlockable(_) => S::Config,
                _ => S::Resolution,
            },
            "INVALID_POM",
            report::render_pom_error(source),
        ),
        ResolveError::LocalPom { path, source } => Diagnostic::new(
            S::Config,
            "INVALID_POM",
            report::render_local_pom_error(path, source),
        ),
        ResolveError::Config(_) => Diagnostic::plain(S::Config, "CONFIG", err.to_string()),
        ResolveError::UnrecordableScope { .. } => {
            Diagnostic::plain(S::Config, "INVALID_POM", err.to_string())
        }
        ResolveError::Io(_) => Diagnostic::plain(S::Failure, "IO", err.to_string()),
        ResolveError::InternalError(_) | ResolveError::MissingRepoClient => {
            Diagnostic::plain(S::Failure, "INTERNAL", err.to_string())
        }
        ResolveError::WorkspaceStalled { .. } => Diagnostic::new(
            S::Failure,
            "INTERNAL",
            Rendered {
                message: err.to_string(),
                hints: vec![
                    "This is a bug in raeva, not in your project; please report it with this message"
                        .to_string(),
                    format!(
                        "Set {} to raise the limit, or to 0 to disable the check",
                        crate::commands::sync::WORKSPACE_STALL_TIMEOUT_ENV
                    ),
                ],
            },
        ),
        ResolveError::UndefinedProperty { property, .. } => {
            let unread = rv_config::unread_jvm_option(property);
            let is_unread = unread.is_some();
            let (severity, code) = match rv_maven_model::jvm_owned(property) || unread.is_some() {
                true => (S::Config, "INVALID_POM"),
                false => (S::Resolution, "RESOLUTION"),
            };
            Diagnostic::new(
            severity,
            code,
            Rendered {
                message: err.to_string(),
                hints: vec![match property.as_str() {
                    property if is_unread => format!(
                        "mvn's JVM may take {property} from its options, where {}, which \
                         raeva cannot read exactly; write that option plainly, or define \
                         {property} on the command line of both raeva and mvn: \
                         -D{property}=<value>",
                        unread.as_deref().unwrap_or_default()
                    ),
                    property if rv_maven_model::jvm_owned(property) => format!(
                        "Maven takes {property} from the JVM, which raeva does not read from \
                         the host or which differs across the hosts the lock covers, so a lock \
                         cannot follow it. Define it in .mvn/maven.config or on the command \
                         line: raeva sync -D{property}=<value>"
                    ),
                    _ => format!(
                        "Define it in .mvn/maven.config or on the command line: raeva sync \
                         -D{}=<value>. In a Maven build a build extension or plugin that raeva \
                         does not run may set it. raeva resolves every reactor module, so one \
                         a build skips with -pl can still fail the sync",
                        rv_maven_types::bounded(property)
                    ),
                }],
            },
        )
        }
        ResolveError::ReadsNoPom { .. } => Diagnostic::new(
            S::Resolution,
            "RESOLUTION",
            Rendered {
                message: err.to_string(),
                hints: vec![
                    "Declare a repository that serves this POM, as a <pluginRepository> for a \
                     plugin, or resolve as Maven 3.10 does, which reads each module's and \
                     plugin's POMs apart, with maven = \"3.10\" under [lock] in raeva.toml"
                        .to_string(),
                ],
            },
        ),
        ResolveError::OnePomPerVersion { .. } => Diagnostic::new(
            S::Resolution,
            "RESOLUTION",
            Rendered {
                message: err.to_string(),
                hints: vec![
                    "Declare one repository that serves this POM for every module and plugin \
                     that reads it"
                        .to_string(),
                ],
            },
        ),
        ResolveError::ReactorModuleUnordered { .. } => Diagnostic::new(
            S::Resolution,
            "RESOLUTION",
            Rendered {
                message: err.to_string(),
                hints: vec![
                    "Declare the reactor module as a <dependency> of the plugin in the POM \
                     that uses it, which makes Maven build it first"
                        .to_string(),
                ],
            },
        ),
        ResolveError::SharedDescriptorDiffers { .. } => Diagnostic::new(
            S::Resolution,
            "RESOLUTION",
            Rendered {
                message: err.to_string(),
                hints: vec![
                    "Declare the repository that serves this POM for every module and plugin \
                     that reads it, as a <pluginRepository> for a plugin. Where one finds no \
                     POM, resolving as Maven 3.10 does, with maven = \"3.10\" under [lock] in \
                     raeva.toml, also locks it"
                        .to_string(),
                ],
            },
        ),
        ResolveError::ConflictingCompanionPomBytes(_)
        | ResolveError::ConflictingSupportCompanionPom { .. } => Diagnostic::new(
            S::Resolution,
            "RESOLUTION",
            Rendered {
                message: err.to_string(),
                hints: vec![
                    "Make one repository serve this POM to every module: remove or restrict \
                     the <repository> that serves the other bytes in the POM that declares it, \
                     or take it off [security] transitive_repository_allowlist, or point a \
                     mirror at the repository you trust (a settings.xml <mirror>, or \
                     [[mirrors]] in config.toml, whose mirror_of is the other repository's id)"
                        .to_string(),
                ],
            },
        ),
        ResolveError::ConflictingPomPackagedBytes { .. } => Diagnostic::new(
            S::Resolution,
            "RESOLUTION",
            Rendered {
                message: err.to_string(),
                hints: vec!["Re-run 'raeva sync --update'".to_string()],
            },
        ),
        ResolveError::ParentBehindWrittenMirror { mirror, .. } => Diagnostic::new(
            S::Resolution,
            "INVALID_POM",
            Rendered {
                message: err.to_string(),
                hints: vec![format!(
                    "If mirror '{mirror}' holds the parent, add its URL as a repository in \
                     raeva.toml"
                )],
            },
        ),
        ResolveError::MirroredImportRepository { id, .. } => Diagnostic::new(
            S::Config,
            "REPOSITORY_CONFIG",
            Rendered {
                message: err.to_string(),
                hints: vec![format!(
                    "Declare repository '{id}' in the project POM or a settings profile, so \
                     the mirror serves it for the project"
                )],
            },
        ),
        ResolveError::RedeclaredRepository { .. } => Diagnostic::new(
            S::Config,
            "REPOSITORY_CONFIG",
            Rendered {
                message: err.to_string(),
                hints: vec!["Allow the redeclared URL with [security] \
                     transitive_repository_allowlist in config.toml, or give the project a \
                     mirror that serves both URLs"
                    .to_string()],
            },
        ),
        ResolveError::UnreadRepositoryAhead { id, .. } => Diagnostic::new(
            S::Config,
            "REPOSITORY_CONFIG",
            Rendered {
                message: err.to_string(),
                hints: vec![format!(
                    "Allow repository '{id}' with [security] transitive_repository_allowlist \
                     in config.toml, or declare it in the project POM"
                )],
            },
        ),
        ResolveError::RepositoryIdUnfollowed { .. } => Diagnostic::new(
            S::Config,
            "REPOSITORY_CONFIG",
            Rendered {
                message: err.to_string(),
                hints: vec!["Write the id out in that POM, or name its value in the \
                     <mirrorOf> of the mirror that should serve it"
                    .to_string()],
            },
        ),
        ResolveError::MirrorRouteSplit { .. } => Diagnostic::new(
            S::Config,
            "REPOSITORY_CONFIG",
            Rendered {
                message: err.to_string(),
                hints: vec![
                    "Give the URL without an expression, or name the repository's id in the \
                     <mirrorOf> of the mirror that should serve it, or exclude it with !id"
                        .to_string(),
                ],
            },
        ),
        ResolveError::NoSnapshotRepository { .. } => Diagnostic::new(
            S::Config,
            "REPOSITORY_CONFIG",
            Rendered {
                message: err.to_string(),
                hints: vec![
                    "Add the repository that publishes this SNAPSHOT to [[repositories]] in \
                     raeva.toml with snapshots = true, or to settings.xml with snapshots \
                     enabled, or depend on a released version"
                        .to_string(),
                ],
            },
        ),
        ResolveError::RelocationCycle(_)
        | ResolveError::WorkspaceDependencyCycle { .. }
        | ResolveError::ReactorChoice { .. }
        | ResolveError::SplitListing { .. }
        | ResolveError::ConflictingArtifactBytes { .. }
        | ResolveError::ConflictingSupportPomBytes(_)
        | ResolveError::ConflictingResolvedPomBytes(_)
        | ResolveError::MissingVersion { .. }
        | ResolveError::InvalidVersionRequirement { .. }
        | ResolveError::VersionNotFound { .. }
        | ResolveError::GraphLimitExceeded { .. }
        | ResolveError::MediationDiverged { .. }
        | ResolveError::UnrecordableSnapshotBuild { .. }
        | ResolveError::PluginSnapshot { .. }
        | ResolveError::UnorderedTestClasspath { .. }
        | ResolveError::ConflictingPluginBytes { .. }
        | ResolveError::UnrecordablePluginPom { .. }
        | ResolveError::UnreadableJar { .. }
        | ResolveError::Version(_) => {
            Diagnostic::plain(S::Resolution, "RESOLUTION", err.to_string())
        }
    }
}

/// Whether `err` lists how the repositories answered for the parent or BOM
/// it misses.
fn names_filtered_model(err: &ResolveError) -> bool {
    match err {
        ResolveError::FilteredModel { .. } => true,
        ResolveError::Declared { error, .. } => names_filtered_model(error),
        _ => false,
    }
}

fn diagnose_export(err: &ExportError, env: &HintEnv) -> Diagnostic {
    use ExitStatus as S;
    let sync = "raeva sync";
    let (status, code, hint) = match err {
        ExportError::StoreError(source) => {
            let rendered = report::render_store_error(source, env);
            return Diagnostic::new(S::Failure, "STORE", rendered);
        }
        ExportError::PinMismatch { .. } => (
            S::LockMismatch,
            "LOCKFILE_MISMATCH",
            Some(format!("Run '{sync}' first")),
        ),
        // A `--platforms` sync downloads only the platforms it names, and an
        // export covers every platform raeva.lock records.
        ExportError::MissingBlob { .. } => (
            S::LockMismatch,
            "LOCKFILE_MISMATCH",
            Some(format!(
                "Run '{sync}' to download the locked files of every platform in raeva.lock, then \
                 retry the export"
            )),
        ),
        // Every sync checks the stored files of raeva.lock and downloads a
        // damaged one again.
        ExportError::CorruptBlob { .. } => (
            S::LockMismatch,
            "LOCKFILE_MISMATCH",
            Some(format!(
                "Run '{sync}' to download the damaged file again, then retry the export"
            )),
        ),
        // Every sync that may reach the network restores the pinned bytes and
        // verifies the digest; `--offline` cannot.
        ExportError::MissingPinnedPom { .. } => (
            S::LockMismatch,
            "LOCKFILE_MISMATCH",
            Some(format!(
                "Run '{sync}' with network access to restore the locked POMs, then retry the export"
            )),
        ),
        ExportError::NotStored(_) => (
            S::LockMismatch,
            "LOCKFILE_MISMATCH",
            Some(format!(
                "Run '{sync}' with network access to download and check every locked file of \
                 every platform, then retry"
            )),
        ),
        ExportError::UnpinnedPom { .. } => (
            S::Config,
            "LOCKFILE_INVALID",
            Some(format!("Run '{sync} --update' to rewrite raeva.lock")),
        ),
        ExportError::ConflictingPinnedPom { .. }
        | ExportError::ConflictingPomPackagedPin { .. }
        | ExportError::ConflictingExportSources { .. } => (
            S::Config,
            "LOCKFILE_INVALID",
            Some(format!("Run '{sync}' to rewrite raeva.lock")),
        ),
        ExportError::EqualSpellings { coordinate, .. } => (
            S::Config,
            "LOCKFILE_INVALID",
            Some(format!(
                "Give {coordinate} one version in the project, such as in \
                 <dependencyManagement>, so that no range chooses between them"
            )),
        ),
        ExportError::UnversionedPlugin { .. } => (
            S::Config,
            "LOCKFILE_INVALID",
            Some(format!(
                "Set [plugins] lock = true in raeva.toml and run '{sync}', or give the plugin \
                 a version in the POM"
            )),
        ),
        ExportError::UnsupportedChecksum { .. }
        | ExportError::ConflictingMarkers { .. }
        | ExportError::SecretOrigin { .. }
        | ExportError::InvalidCoordinate(_)
        | ExportError::WindowsUnsafeName { .. }
        | ExportError::ShortNameAlias { .. } => (S::Config, "LOCKFILE_INVALID", None),
        // The coordinates are valid by now: a link inside the destination
        // leads out of it.
        ExportError::PathTraversal(_) | ExportError::Destination { .. } => {
            (S::Config, "LOCAL_REPOSITORY", None)
        }
        ExportError::DestinationCollision { .. } => (
            S::Config,
            "LOCAL_REPOSITORY",
            Some(
                "--overwrite does not help, as both need that path; when one is a sources or \
                 javadoc file, export without --with-sources or --with-javadocs"
                    .to_string(),
            ),
        ),
        ExportError::CaseCollision { path, .. } | ExportError::PlanCaseCollision { path, .. } => {
            let metadata = path.file_name().is_some_and(|name| {
                let name = name.to_string_lossy();
                name.starts_with("maven-metadata-")
                    && (name.ends_with(".xml") || name.contains(".xml."))
            });
            let export = match err {
                ExportError::PlanCaseCollision { .. } => "--m2-path in place of --plan-json",
                _ => "--m2-path",
            };
            let hint = if metadata {
                format!(
                    "Rename the repositories so that their ids differ in more than letter case \
                     or Unicode normalization, or export with {export} to a volume that keeps \
                     the names apart"
                )
            } else {
                format!(
                    "Export with {export} to a volume that keeps the names apart: a \
                     case-sensitive one, though APFS treats names that differ only in Unicode \
                     normalization as one either way"
                )
            };
            (S::Config, "LOCAL_REPOSITORY", Some(hint))
        }
        ExportError::DestinationMismatch { .. } => (
            S::Failure,
            "EXPORT",
            Some("Rerun with --overwrite to replace it".to_string()),
        ),
        // `ExportError` is non-exhaustive: an error this build predates is a
        // plain export failure.
        _ => (S::Failure, "EXPORT", None),
    };
    let rendered = Rendered {
        message: format!("export error: {err}"),
        hints: hint.into_iter().collect(),
    };
    Diagnostic::new(status, code, rendered)
}

/// The ids whose credential sync takes from a settings.xml username and
/// password, as `AuthStore::lookup_auth` picks it: the first entry of a file
/// for the id decides, unless it has none of the fields raeva reads, when
/// the next file does.
fn settings_password_ids(config: &rv_config::Config) -> Vec<String> {
    let layers = config.auth_layers();
    let mut ids: Vec<String> = Vec::new();
    for id in layers
        .settings()
        .iter()
        .filter_map(|entry| entry.id.as_deref())
    {
        let picked = [layers.project(), layers.user(), layers.settings()]
            .into_iter()
            .enumerate()
            .filter_map(|(file, entries)| {
                let entry = entries
                    .iter()
                    .find(|entry| entry.id.as_deref() == Some(id))?;
                (entry.token.is_some() || entry.username.is_some() || entry.password.is_some())
                    .then_some((file == 2, entry))
            })
            .next();
        if matches!(picked, Some((true, entry)) if entry.token.is_none())
            && !ids.iter().any(|known| known == id)
        {
            ids.push(id.to_string());
        }
    }
    ids
}

#[cfg(test)]
mod tests {
    use super::{CliError, ExitStatus, HintEnv};
    use rv_repo::RepoError;
    use rv_resolver::ResolveError;

    fn env() -> HintEnv {
        HintEnv {
            store_dir: Some("/home/u/.raeva/store".into()),
            user_config: Some("/home/u/.config/raeva/config.toml".into()),
            metadata_cache: Some("/home/u/.raeva/metadata.db".into()),
            settings_file: None,
            env_proxies: Vec::new(),
            file_proxies: Vec::new(),
            credential_scope: None,
            dropped_passwords: Vec::new(),
        }
    }

    /// The metadata cache is `metadata.db` beside the store, not the cache
    /// directory, so deleting what its errors name clears it.
    #[test]
    fn metadata_cache_errors_name_metadata_db() {
        let paths = rv_config::ResolvedPaths::from_raeva_home("/home/u/raeva");
        assert_eq!(
            HintEnv::from_paths(Some(&paths)).metadata_cache_location(),
            paths.metadata_db_path().display().to_string()
        );
    }

    fn status(err: CliError) -> ExitStatus {
        err.diagnose(&env()).status
    }

    fn timeout() -> RepoError {
        RepoError::Transfer(std::io::Error::new(std::io::ErrorKind::TimedOut, "slow"))
    }

    /// A transient failure during resolution is a network failure, whether
    /// or not resolution recorded the repositories it searched.
    #[test]
    fn network_errors_under_resolution_exit_network() {
        assert_eq!(
            status(CliError::Resolve(ResolveError::Repo {
                coord: Some("g:a:1".to_string()),
                source: Box::new(timeout()),
                searched: Vec::new(),
            })),
            ExitStatus::Network
        );
        assert_eq!(status(CliError::Repo(timeout())), ExitStatus::Network);
    }

    /// docs/json-output.md lists every error code this file can give, once,
    /// and no other. Every `code` comes from a string literal here, so the
    /// codes are the upper-case literals above the tests.
    #[test]
    fn the_docs_list_exactly_the_error_codes() {
        let source =
            rv_test_support::fixtures::without_inline_test_module(include_str!("diagnose.rs"));
        let in_code: std::collections::BTreeSet<String> =
            rv_test_support::fixtures::uppercase_string_literals(&source)
                .into_iter()
                .map(|(_, code)| code.to_string())
                .collect();
        let documented = rv_test_support::fixtures::markdown_first_column(
            &rv_test_support::fixtures::workspace_file("docs/json-output.md"),
            "## Error codes",
        );
        let listed: std::collections::BTreeSet<String> = documented.iter().cloned().collect();
        assert_eq!(listed.len(), documented.len(), "a code is listed twice");
        assert_eq!(listed, in_code, "docs/json-output.md error table");
    }

    /// The Exit column of the error table in docs/json-output.md names every
    /// status this file gives a code: the status written beside the code
    /// in the same call or tuple, and for a repository error class, the
    /// class's status. A status of 1 for a code only `raeva vuln` gives is
    /// documented as the 2 that `raeva vuln` exits with.
    #[test]
    fn the_docs_give_the_exit_status_of_every_error_code() {
        use super::{ErrorClass, class_code};
        use rv_repo::IntegritySource;
        use strum::IntoEnumIterator;

        let documented: std::collections::BTreeMap<String, Vec<u8>> =
            rv_test_support::fixtures::markdown_table(
                &rv_test_support::fixtures::workspace_file("docs/json-output.md"),
                "## Error codes",
            )
            .into_iter()
            .map(|row| {
                let exits = row[1]
                    .split(|c: char| !c.is_ascii_digit())
                    .filter(|number| !number.is_empty())
                    .map(|number| number.parse::<u8>().expect("exit status"))
                    .collect();
                (row[0].clone(), exits)
            })
            .collect();
        let by_name: std::collections::BTreeMap<String, ExitStatus> = ExitStatus::iter()
            .map(|status| (format!("{status:?}"), status))
            .collect();
        let mut given: Vec<(String, ExitStatus)> = Vec::new();

        let source =
            rv_test_support::fixtures::without_inline_test_module(include_str!("diagnose.rs"));
        for (index, code) in rv_test_support::fixtures::uppercase_string_literals(&source) {
            let call = &source[..index];
            let call = &call[call.rfind('(').unwrap_or(0)..];
            let status = ["S::", "ExitStatus::"].iter().find_map(|prefix| {
                let at = call.rfind(prefix)?;
                let name: String = call[at + prefix.len()..]
                    .chars()
                    .take_while(char::is_ascii_alphanumeric)
                    .collect();
                by_name.get(&name).copied()
            });
            if let Some(status) = status {
                given.push((code.to_string(), status));
            }
        }
        let classes = [
            ErrorClass::Auth,
            ErrorClass::ProxyAuth,
            ErrorClass::Network,
            ErrorClass::Tls,
            ErrorClass::Config,
            ErrorClass::Integrity(IntegritySource::Sidecar),
            ErrorClass::Integrity(IntegritySource::LockPin),
            ErrorClass::NotFound,
            ErrorClass::Store,
            ErrorClass::Offline,
            ErrorClass::Lockfile,
            ErrorClass::Internal,
            ErrorClass::Other,
        ];
        for class in classes {
            // A new class fails to compile here until it is listed above.
            match class {
                ErrorClass::Auth
                | ErrorClass::ProxyAuth
                | ErrorClass::Network
                | ErrorClass::Tls
                | ErrorClass::Config
                | ErrorClass::Integrity(_)
                | ErrorClass::NotFound
                | ErrorClass::Store
                | ErrorClass::Offline
                | ErrorClass::Lockfile
                | ErrorClass::Internal
                | ErrorClass::Other => {}
            }
            given.push((class_code(class).to_string(), class.exit_status()));
        }

        assert!(given.len() > 40, "the scan found {} codes", given.len());
        for (code, status) in given {
            let exits = documented
                .get(&code)
                .unwrap_or_else(|| panic!("{code} is not documented"));
            let shown = if code == "VULNERABILITY_SERVICE" {
                status.of_failed_scan()
            } else {
                status
            };
            assert!(
                exits.contains(&shown.code()),
                "{code} exits {} ({status:?}), but docs/json-output.md gives {exits:?}",
                shown.code()
            );
        }
    }

    /// What each kind of error tells the user, pinned in a golden file: the
    /// code, the exit status, the message and the suggestions.
    #[test]
    fn errors_render_as_the_golden_file_shows() {
        use rv_export::ExportError as Export;
        use rv_maven_model::PomError;
        use rv_resolver::{DroppedRepo, RepoSearchStatus, RepoStatus};
        use rv_store::StoreError as Store;
        use rv_store::metadata_cache::CacheError as Cache;
        use rv_vuln::{FailedFetch, VulnError};
        use std::io::ErrorKind;

        let s = |text: &str| text.to_string();
        let io = |kind| std::io::Error::new(kind, "io detail");
        let sqlite = |code| rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(code), None);
        let db = |code| Store::DbContext {
            ctx: s("open"),
            source: sqlite(code),
        };
        let pool = || Store::PoolError(s("busy"));
        let newer = |file: &str| Store::NewerDatabase {
            path: format!("/raeva/{file}").into(),
            found: 2,
            supported: 1,
        };
        let searched =
            |code| RepoSearchStatus::new("https://repo.example/m2/", RepoStatus::Http(code));
        let refused_with = |code, id: Option<&str>, sent| {
            let mut status = searched(code);
            let (id, url) = (id.map(s), s("https://repo.example/m2/"));
            status.refused_by = Some(rv_resolver::CredentialTarget { id, url, sent });
            status
        };
        let refused = |code, id| refused_with(code, id, None);
        let sent = |id: &str, file, unset: &[&str]| {
            Some(rv_repo::SentCredential {
                id: Some(s(id)),
                file,
                unset_variables: unset.iter().map(|name| s(name)).collect(),
            })
        };
        let unset = sent("raeva", rv_repo::CredentialFile::Settings, &["RAEVA_TOKEN"]);
        let wrong = sent("raeva", rv_repo::CredentialFile::Settings, &[]);
        let user = sent("corp", rv_repo::CredentialFile::User, &[]);
        let repo = |source, searched| {
            ResolveError::Repo {
                coord: Some(s("g:a:1")),
                source: Box::new(source),
                searched,
            }
            .into()
        };
        let auth = |code| RepoError::Unauthorized {
            status: reqwest::StatusCode::from_u16(code).unwrap(),
            url: s("https://repo.example/m2/a.pom"),
            sent: None,
        };
        let pom = |err| CliError::Resolve(ResolveError::Pom(err));
        let malformed = || PomError::NotWellFormed {
            reason: "bad",
            line: 3,
        };
        let not_found = |coord: &str, searched| ResolveError::ArtifactNotFound {
            coord: s(coord),
            searched,
            dropped_repos: Vec::new(),
            classifier_like: None,
        };
        let mut dropped = not_found("g:a:1", vec![searched(404)]);
        if let ResolveError::ArtifactNotFound { dropped_repos, .. } = &mut dropped {
            for url in ["https://corp.example/a/", "https://corp.example/a"] {
                let declared_by = s("g:dep:1");
                let (releases_enabled, snapshots_enabled) = (true, false);
                dropped_repos.push(DroppedRepo {
                    url: s(url),
                    declared_by,
                    releases_enabled,
                    snapshots_enabled,
                    http_blocked: false,
                });
            }
            dropped_repos.push(DroppedRepo {
                url: s("http://old.example/m2/"),
                declared_by: s("g:legacy:1"),
                releases_enabled: true,
                snapshots_enabled: false,
                http_blocked: true,
            });
        }
        let fetch = |n, error| {
            let purls = (0..4).map(|p| format!("pkg:maven/g/a{p}@1")).collect();
            FailedFetch::new(format!("GHSA-{n}"), purls, std::sync::Arc::new(error))
        };
        let shared = (0..12)
            .map(|n| fetch(n, VulnError::InvalidResponse(s("x"))))
            .collect();
        let mixed = vec![
            fetch(1, VulnError::RateLimited { retry_after: None }),
            fetch(2, VulnError::InvalidPurl(s("x"))),
        ];
        let errors: Vec<CliError> = vec![
            Store::IoError(io(ErrorKind::StorageFull)).into(),
            Store::IoError(io(ErrorKind::QuotaExceeded)).into(),
            Store::IoError(io(ErrorKind::PermissionDenied)).into(),
            Store::IoError(io(ErrorKind::NotFound)).into(),
            Store::IoError(io(ErrorKind::Other)).into(),
            db(13).into(),
            db(14).into(),
            db(11).into(),
            db(1).into(),
            db(rusqlite::ffi::SQLITE_IOERR_SHMSIZE).into(),
            Store::IntegrityError(s("bad")).into(),
            Store::LockTimeout {
                path: "lock".into(),
                holder_info: s("pid 7"),
            }
            .into(),
            newer("index.sqlite").into(),
            ResolveError::Store(pool()).into(),
            Export::StoreError(pool()).into(),
            RepoError::Cache(Cache::Db {
                ctx: s("read"),
                source: Box::new(sqlite(1)),
            })
            .into(),
            RepoError::Cache(Cache::Pool(s("x"))).into(),
            RepoError::Cache(Cache::Io(io(ErrorKind::Other))).into(),
            RepoError::Cache(Cache::Io(io(ErrorKind::StorageFull))).into(),
            RepoError::Cache(Cache::Setup(Box::new(pool()))).into(),
            RepoError::Cache(Cache::Setup(Box::new(newer("metadata.db")))).into(),
            RepoError::Cache(Cache::Setup(Box::new(db(
                rusqlite::ffi::SQLITE_IOERR_SHMSIZE,
            ))))
            .into(),
            RepoError::Store(pool()).into(),
            RepoError::UnpinnedLockRow(s("g:a:1")).into(),
            RepoError::InvalidMetadata(s("bad xml")).into(),
            RepoError::AuthSetup(s("no token")).into(),
            auth(407).into(),
            repo(auth(403), vec![refused(403, None)]),
            repo(auth(401), vec![refused(401, Some("9a\\b"))]),
            repo(auth(401), vec![refused_with(401, Some("raeva"), wrong)]),
            repo(auth(401), vec![refused_with(401, Some("raeva"), unset)]),
            repo(auth(403), vec![refused_with(403, Some("corp"), user)]),
            repo(timeout(), Vec::new()),
            repo(
                RepoError::HttpStatus {
                    status: reqwest::StatusCode::TOO_MANY_REQUESTS,
                    url: s("https://repo.example/m2/a.pom"),
                    retry_after: None,
                },
                Vec::new(),
            ),
            repo(
                RepoError::HttpStatus {
                    status: reqwest::StatusCode::INTERNAL_SERVER_ERROR,
                    url: s("https://repo.example/m2/a.pom"),
                    retry_after: None,
                },
                vec![searched(500)],
            ),
            pom(PomError::ParentNotFound(s("g"), s("p"), s("1-SNAPSHOT"))),
            pom(PomError::InvalidSystemPath(s("x"))),
            pom(malformed()),
            pom(PomError::MissingField("version")),
            ResolveError::LocalPom {
                path: s("app/pom.xml"),
                source: malformed(),
            }
            .into(),
            dropped.into(),
            not_found("g:a:1", Vec::new()).into(),
            ResolveError::Declared {
                module: s("app/pom.xml"),
                via: vec![s("g:dep:1")],
                error: Box::new(not_found(
                    "g:a:1",
                    vec![RepoSearchStatus::new(
                        "https://repo1.maven.org/maven2/",
                        RepoStatus::Http(404),
                    )],
                )),
            }
            .into(),
            not_found("g:a:1", {
                let mut central =
                    RepoSearchStatus::new("https://repo1.maven.org/maven2/", RepoStatus::Http(404));
                central.served_by = Some(s("https://mirror.example/all/"));
                vec![central]
            })
            .into(),
            ResolveError::NoSnapshotRepository {
                coord: s("g:a:1.0-SNAPSHOT"),
                message: s("none of the configured repositories (central) have snapshots enabled"),
            }
            .into(),
            // Two declarations of Central behind different mirrors.
            not_found("g:a:1", {
                let mirrored = |url: &str, mirror: &str| {
                    let mut status = RepoSearchStatus::new(url, RepoStatus::Http(404));
                    status.served_by = Some(s(mirror));
                    status
                };
                vec![
                    mirrored(
                        "https://repo1.maven.org/maven2/",
                        "https://mirror.example/a/",
                    ),
                    mirrored(
                        "https://repo.maven.apache.org/maven2/",
                        "https://mirror.example/b/",
                    ),
                ]
            })
            .into(),
            ResolveError::Declared {
                module: s("app/pom.xml"),
                via: Vec::new(),
                error: Box::new(ResolveError::MissingVersion {
                    group_id: s("g"),
                    artifact_id: s("a"),
                }),
            }
            .into(),
            ResolveError::MultipleArtifactErrors {
                first: Box::new(ResolveError::NoRepositories),
                rest: (0..12)
                    .map(|n| not_found(&format!("g:a:{n}"), Vec::new()))
                    .collect(),
            }
            .into(),
            ResolveError::VersionConflict {
                coord: s("g:a"),
                requested: s("1"),
                selected: s("2"),
            }
            .into(),
            ResolveError::Io(io(ErrorKind::Other)).into(),
            CliError::IoWithPath {
                path: "/p/raeva.lock".into(),
                source: io(ErrorKind::PermissionDenied),
            },
            ResolveError::InternalError(s("x")).into(),
            ResolveError::Plugin {
                plugin: s("plugin t:p:1-SNAPSHOT"),
                searched: Vec::new(),
                error: Box::new(ResolveError::PluginSnapshot {
                    coord: s("t:p:1-SNAPSHOT:jar"),
                }),
            }
            .into(),
            ResolveError::ConflictingPluginBytes {
                coord: s("t:p:1:jar"),
            }
            .into(),
            ResolveError::WorkspaceStalled {
                modules: s("app"),
                stalled_for_secs: 9,
            }
            .into(),
            ResolveError::ConflictingPomPackagedBytes {
                coord: s("g:a"),
                artifact_sha256: s("1"),
                pom_sha256: s("2"),
            }
            .into(),
            ResolveError::RelocationCycle(s("a -> b")).into(),
            Export::PinMismatch {
                key: s("k"),
                algorithm: s("sha256"),
                expected: s("1"),
                actual: s("2"),
            }
            .into(),
            Export::MissingBlob { key: s("k") }.into(),
            Export::CorruptBlob {
                path: "/home/u/.raeva/store/blobs/1".into(),
                actual: s("2"),
                expected: s("1"),
            }
            .into(),
            Export::MissingPinnedPom {
                coordinate: s("k"),
                digest: s("1"),
            }
            .into(),
            Export::UnpinnedPom { coordinate: s("k") }.into(),
            Export::InvalidCoordinate(s("k")).into(),
            Export::PathTraversal("x".into()).into(),
            Export::CaseCollision {
                first: s("A"),
                second: s("a"),
                path: "x".into(),
            }
            .into(),
            Export::PlanCaseCollision {
                first: s("A"),
                second: s("a"),
                path: "x".into(),
            }
            .into(),
            Export::DestinationMismatch {
                key: s("k"),
                path: "x".into(),
                expected: s("1"),
                actual: s("2"),
            }
            .into(),
            Export::IoError(io(ErrorKind::Other)).into(),
            CliError::VulnRecordsUnfetched { failures: shared },
            CliError::VulnerabilityScan(Box::new(CliError::VulnRecordsUnfetched {
                failures: mixed,
            })),
            CliError::Download {
                failures: vec![s("g:a:1: gone")],
                first: RepoError::NotFound(s("a").into()),
            },
            CliError::Download {
                failures: (0..12).map(|n| format!("g:a{n}:1: refused")).collect(),
                first: auth(401),
            },
            CliError::PlatformMissing {
                platform: s("linux-x86_64"),
                recorded: vec![s("darwin-arm64")],
                frozen: false,
            },
            CliError::PlatformMissing {
                platform: s("linux-x86_64"),
                recorded: vec![s("macos-aarch64"), s("windows-x86_64")],
                frozen: true,
            },
            CliError::OtherPlatformOrigin {
                file: s("org.test:s:1:jar"),
                repo: s("https://repo-b.example/"),
                platforms: vec![s("windows-x86_64")],
            },
            CliError::LockfileTooNew {
                found: 10,
                expected: 9,
            },
            CliError::LockfileMissing {
                path: "/p/raeva.lock".into(),
                sync_creates: true,
                reactor: None,
            },
            CliError::ProjectFileMissing {
                path: "pom.xml".into(),
            },
            CliError::LockfileBusy {
                project_root: "p".into(),
                source: io(ErrorKind::TimedOut),
            },
            io(ErrorKind::Other).into(),
            CliError::Sbom(rv_sbom::SbomError::InvalidComponent(s("x"))),
            CliError::Message(s("plain")),
            CliError::Usage(s("x")),
            CliError::RepositoryOriginAlias {
                origin: s("./repo/"),
                first: s("a"),
                second: s("b"),
            },
            CliError::DoctorChecksFailed {
                failed: 1,
                status: ExitStatus::Partial,
            },
        ];
        let rendered: Vec<String> = errors
            .iter()
            .map(|err| {
                let diagnostic = err.diagnose(&env());
                format!(
                    "{} {:?}\n{}",
                    diagnostic.code,
                    diagnostic.status,
                    diagnostic.human()
                )
            })
            .collect();
        let golden = rv_test_support::fixtures::path("error-golden/diagnostics.txt");
        rv_test_support::golden::assert_golden(&golden, &rendered.join("\n----\n"));
    }
}
