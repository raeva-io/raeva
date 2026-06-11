use rv_maven_model::PomError;
use rv_repo::{RepoError, is_snapshot_version};
use rv_resolver::{RepoSearchStatus, RepoStatus, ResolveError};
use rv_store::StoreError;
use std::fmt::Write;

/// Maximum number of nested errors rendered inside a
/// `MultipleArtifactErrors` block. Anything beyond this is summarized
/// with "... and N more" so the CLI output stays scannable.
const MAX_NESTED_ERRORS: usize = 5;

/// Redact credentials and query-string tokens from a URL string.
///
/// Strips `user:pass@` userinfo and replaces every query-parameter value with
/// `***` so tokens embedded as `?token=abc` or `?api_key=xyz` never reach
/// user-visible error output. The host, path, and parameter *names* are
/// preserved so the URL is still recognisable for debugging.
///
/// Returns the original string unchanged if it cannot be parsed as a URL.
pub(crate) fn redact_url(raw: &str) -> String {
    let Ok(mut url) = url::Url::parse(raw) else {
        return raw.to_string();
    };
    // Strip userinfo (user:pass@host).
    let _ = url.set_username("");
    let _ = url.set_password(None);
    // Replace every query-parameter value with "***".
    if url.query().is_some() {
        let pairs: Vec<(String, String)> = url
            .query_pairs()
            .map(|(k, _)| (k.into_owned(), "***".to_string()))
            .collect();
        if pairs.is_empty() {
            url.set_query(None);
        } else {
            let redacted = pairs
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("&");
            url.set_query(Some(&redacted));
        }
    }
    url.to_string()
}

pub(crate) fn render_resolve_error(err: &ResolveError) -> String {
    // Exhaustive match: a `_ =>` catch-all silently swallows new variants when
    // `rv-resolver` grows, hiding actionable diagnostics behind the plain
    // `Display` rendering. Listing every variant forces the compiler to flag
    // future additions so they get an explicit decision here.
    match err {
        ResolveError::ArtifactNotFound { coord, searched } => {
            render_dependency_not_found(coord, searched)
        }
        ResolveError::NoRepositories => render_no_repositories(),
        ResolveError::VersionConflict {
            coord,
            requested,
            selected,
        } => render_version_conflict(coord, requested, selected),
        ResolveError::RepoWithContext { source, searched } => {
            render_repo_error(source, Some(searched))
        }
        ResolveError::Repo(source) => render_repo_error(source, None),
        ResolveError::Pom(err) => render_pom_error(err),
        ResolveError::LocalPom { path, source } => render_local_pom_error(path, source),
        ResolveError::MultipleArtifactErrors { first, rest } => {
            render_multiple_artifact_errors(first, rest)
        }
        ResolveError::RelocationCycle(_)
        | ResolveError::MissingVersion { .. }
        | ResolveError::InvalidVersionRequirement { .. }
        | ResolveError::VersionNotFound { .. }
        | ResolveError::QueueLimitExceeded { .. }
        | ResolveError::MissingRepoClient
        | ResolveError::NoSnapshotRepository { .. }
        | ResolveError::Config(_)
        | ResolveError::Store(_)
        | ResolveError::Version(_)
        | ResolveError::Io(_)
        | ResolveError::SolverInvariant { .. }
        | ResolveError::InternalError(_) => err.to_string(),
    }
}

fn render_multiple_artifact_errors(first: &ResolveError, rest: &[ResolveError]) -> String {
    let total = 1 + rest.len();
    let mut out = String::new();
    let _ = writeln!(out, "{total} artifact fetch error(s):");
    out.push('\n');
    out.push_str(&render_resolve_error(first));
    for nested in rest.iter().take(MAX_NESTED_ERRORS - 1) {
        out.push_str("\n---\n\n");
        out.push_str(&render_resolve_error(nested));
    }
    if rest.len() > MAX_NESTED_ERRORS - 1 {
        let _ = writeln!(
            out,
            "\n... and {} more",
            rest.len() - (MAX_NESTED_ERRORS - 1)
        );
    }
    out
}

pub(crate) fn render_repo_error(err: &RepoError, searched: Option<&[RepoSearchStatus]>) -> String {
    if is_auth_error(err) {
        return render_auth_error(err, searched);
    }
    if is_network_error(err) {
        return render_network_error(err, searched);
    }
    if is_invalid_metadata(err) {
        return render_invalid_metadata(err, searched);
    }

    let mut out = String::new();
    let _ = writeln!(out, "Repository error: {err}");
    append_searched_section(&mut out, searched);
    out
}

pub(crate) fn render_pom_error(err: &PomError) -> String {
    match err {
        PomError::ParentNotFound(group, artifact, version) => {
            let coord = format!("{group}:{artifact}:{version}");
            let mut out = String::new();
            let _ = writeln!(out, "Parent POM not found: {coord}");
            out.push_str("\n  This parent POM could not be resolved.\n");
            out.push_str("\n  Suggestions:\n");
            if is_snapshot_version(version) {
                out.push_str("    - SNAPSHOT parents require a repository with snapshots = true\n");
            }
            out.push_str("    - If the parent is internal, add its repository to rv.toml\n");
            out
        }
        PomError::InvalidModel(msg) if msg.contains("systemPath") => {
            // Surface a focused remediation for system-scope misuse rather
            // than the generic "Invalid POM metadata / run rv doctor" hint.
            // `rv doctor` cannot diagnose a missing or relative
            // `<systemPath>` element inside a local pom.xml.
            let mut out = String::new();
            let _ = writeln!(out, "Local POM error: {msg}");
            out.push_str("\n  Suggestions:\n");
            out.push_str("    - Add <systemPath>/absolute/path/to/jar</systemPath>\n");
            out.push_str(
                "    - Or switch the dependency away from system scope (system scope is non-portable).\n",
            );
            out
        }
        _ => {
            let mut out = String::new();
            let _ = writeln!(out, "Invalid POM metadata: {err}");
            out.push_str("\n  The POM could not be parsed.\n");
            out.push_str("\n  Suggestions:\n");
            out.push_str(
                "    - Verify the repository is serving a valid POM (not HTML or an error page)\n",
            );
            out.push_str("    - Run 'rv doctor' to diagnose repository connectivity\n");
            out
        }
    }
}

fn render_local_pom_error(path: &str, err: &rv_maven_model::PomError) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Invalid pom.xml: {err}");
    out.push_str(&format!("\n  File: {path}\n"));
    out.push_str("\n  Suggestions:\n");
    out.push_str("    - Check for XML syntax errors (unclosed tags, unescaped characters)\n");
    out.push_str(
        "    - Verify the file is valid XML by opening it in a browser or XML validator\n",
    );
    out.push_str("    - Run 'mvn validate' to check POM validity\n");
    out
}

pub(crate) fn render_reqwest_error(err: &reqwest::Error) -> String {
    // `reqwest::Error::Display` appends " for url (<url>)" which may contain
    // query-string tokens (e.g. `?token=abc`). Strip the raw URL suffix from
    // the Display string and re-attach a redacted form so the host is still
    // visible for debugging while credentials stay out of error output.
    let raw = err.to_string();
    // The Display impl appends " for url (<url>)". Strip that suffix and
    // replace it with the redacted URL.
    let base_msg = if let Some(pos) = raw.rfind(" for url (") {
        raw[..pos].to_string()
    } else {
        raw
    };
    let url_suffix = err
        .url()
        .map(|u| format!(" (url: {})", redact_url(u.as_str())))
        .unwrap_or_default();
    let message = format!("HTTP request error: {base_msg}{url_suffix}");
    if err.is_timeout() || err.is_connect() {
        return with_doctor_hint(message);
    }
    message
}

fn render_dependency_not_found(coord: &str, searched: &[RepoSearchStatus]) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Dependency not found: {coord}");
    if searched.is_empty() {
        out.push_str("\n  This artifact was not found in any configured repository.\n");
    } else {
        let _ = writeln!(
            out,
            "\n  Searched {} repository(s): {}",
            searched.len(),
            searched
                .iter()
                .map(|s| redact_url(&s.repo_url))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    append_searched_section(&mut out, Some(searched));
    out.push_str("\n  If this is an internal artifact, add the private repository to [[repositories]] in rv.toml or settings.xml.\n");
    out.push_str("\n  Suggestions:\n");
    out.push_str("    - Check if the coordinates are correct\n");
    out.push_str("    - The artifact may be in a private repository; add it to rv.toml:\n");
    out.push_str("\n      [[repositories]]\n");
    out.push_str("      id = \"private\"\n");
    out.push_str("      url = \"https://your-repo.example.com/maven/\"\n");
    out.push_str("\n    - Or add the repository to your Maven settings.xml:\n");
    out.push_str("\n      <repository>\n");
    out.push_str("        <id>private</id>\n");
    out.push_str("        <url>https://your-repo.example.com/maven/</url>\n");
    out.push_str("      </repository>\n");
    out.push_str("\n    - For Android artifacts, Google Maven is searched by default\n");
    out.push_str("    - Run 'rv doctor' to diagnose repository connectivity\n");
    out
}

fn render_no_repositories() -> String {
    let mut out = String::new();
    let _ = writeln!(out, "No repositories configured");
    out.push_str("\n  Dependency resolution requires at least one repository.\n");
    out.push_str("\n  Suggestions:\n");
    out.push_str("    - Add a repository to rv.toml:\n");
    out.push_str("\n      [[repositories]]\n");
    out.push_str("      id = \"central\"\n");
    out.push_str("      url = \"https://repo1.maven.org/maven2/\"\n");
    out.push_str("\n    - Run 'rv doctor' to verify configuration\n");
    out
}

fn render_version_conflict(coord: &str, requested: &str, selected: &str) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Version conflict: {coord}");
    out.push_str(&format!("\n  Requested: {requested}\n"));
    out.push_str(&format!("  Selected: {selected}\n"));
    out.push_str("\n  Suggestions:\n");
    out.push_str("    - Add a direct dependency in rv.toml to pin the version\n");
    out.push_str(
        "    - Try a different strategy: 'rv sync --strategy highest' or 'rv sync --strategy nearest'\n",
    );
    out.push_str("    - Run 'rv tree' to locate conflicting requests\n");
    out
}

fn render_auth_error(err: &RepoError, searched: Option<&[RepoSearchStatus]>) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Authentication required for repository access");
    if let Some(code) = err.status_code() {
        let _ = writeln!(out, "\n  The repository returned HTTP {code}.");
    } else {
        let _ = writeln!(out, "\n  {err}");
    }
    append_searched_section(&mut out, searched);
    out.push_str("\n  Suggestions:\n");
    out.push_str("    - Add credentials in rv.toml:\n");
    out.push_str("\n      [[auth]]\n");
    out.push_str("      id = \"private\"\n");
    out.push_str("      username = \"your-username\"\n");
    out.push_str("      password = \"your-password\"\n");
    out.push_str("\n    - If using a token, set token = \"...\" instead\n");
    out.push_str("    - Run 'rv doctor' to diagnose repository connectivity\n");
    out
}

fn render_network_error(err: &RepoError, searched: Option<&[RepoSearchStatus]>) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Network error while accessing repositories");
    let _ = writeln!(out, "\n  {err}");
    append_searched_section(&mut out, searched);
    out.push_str("\n  Suggestions:\n");
    out.push_str("    - Check your network connection and proxy settings\n");
    out.push_str("    - If you are behind a proxy, configure it in rv.toml\n");
    out.push_str("    - Run 'rv doctor' to diagnose repository connectivity\n");
    out
}

fn render_invalid_metadata(err: &RepoError, searched: Option<&[RepoSearchStatus]>) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Invalid repository metadata: {err}");
    out.push_str("\n  The POM or metadata could not be parsed.\n");
    append_searched_section(&mut out, searched);
    out.push_str("\n  Suggestions:\n");
    out.push_str(
        "    - Verify the repository is serving valid metadata (not HTML or an error page)\n",
    );
    out.push_str("    - Try 'rv sync --update' to refetch metadata\n");
    out.push_str("    - Run 'rv doctor' to diagnose repository connectivity\n");
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
        let status = format_repo_status(&entry.status);
        // Redact credentials from the repository URL before printing. A user
        // may have configured `https://user:pass@repo.example.com/` in rv.toml;
        // that would appear verbatim in `ArtifactNotFound` and similar errors
        // without this guard.
        let safe_url = redact_url(&entry.repo_url);
        let _ = writeln!(out, "    - {} ({})", safe_url, status);
    }
}

fn format_repo_status(status: &RepoStatus) -> String {
    match status {
        RepoStatus::Http(code) => code.to_string(),
        RepoStatus::Error(label) => (*label).to_string(),
    }
}

fn is_auth_error(err: &RepoError) -> bool {
    matches!(err, RepoError::AuthError(_)) || matches!(err.status_code(), Some(401 | 403))
}

fn is_network_error(err: &RepoError) -> bool {
    err.is_transient()
}

fn is_invalid_metadata(err: &RepoError) -> bool {
    matches!(err, RepoError::InvalidMetadata(_) | RepoError::Xml(_))
}

/// Produce a user-facing message for artifact store errors.
///
/// Avoids leaking rusqlite internals such as
/// `SqliteFailure(Error { code: DiskFull, extended_code: … }, …)`.
pub(crate) fn render_store_error(err: &StoreError) -> String {
    match err {
        StoreError::LockTimeout { .. } => {
            // `StoreError::LockTimeout` already carries a detailed, user-actionable
            // message (process info, advice on NOT deleting the lock file). Surface
            // it verbatim; it does not contain internal implementation details.
            err.to_string()
        }
        StoreError::IoError(io_err) => {
            use std::io::ErrorKind;
            match io_err.kind() {
                ErrorKind::StorageFull | ErrorKind::OutOfMemory => {
                    "artifact store error: disk full; check available space on the store volume"
                        .to_string()
                }
                ErrorKind::PermissionDenied => {
                    "artifact store error: permission denied accessing the .raeva store; check directory permissions".to_string()
                }
                ErrorKind::NotFound => {
                    "artifact store error: store file or directory not found; run 'rv sync' to initialise the store".to_string()
                }
                _ => format!("artifact store error: I/O error: {io_err}"),
            }
        }
        StoreError::DbError(db_err) => {
            // Inspect the error Display string to classify the most common
            // actionable SQLite error codes without requiring `rusqlite` as a
            // direct rv-cli dependency (it is transitive via rv-store).
            let db_str = db_err.to_string().to_lowercase();
            if db_str.contains("disk full") || db_str.contains("diskfull") {
                return "artifact store error: disk full; check available space on the store volume".to_string();
            }
            if db_str.contains("cannotopen") || db_str.contains("cannot open") {
                return "artifact store error: cannot open the artifact database; check directory permissions".to_string();
            }
            if db_str.contains("databasecorrupt") || db_str.contains("corrupt") {
                return "artifact store error: the artifact database is corrupt; delete ~/.raeva/store and run 'rv sync'".to_string();
            }
            "artifact store error: database error; try running 'rv sync' again; if the problem persists, delete ~/.raeva/store".to_string()
        }
        StoreError::DbContext { ctx, source } => {
            let src_str = source.to_string().to_lowercase();
            if src_str.contains("disk full") || src_str.contains("diskfull") {
                return "artifact store error: disk full; check available space on the store volume".to_string();
            }
            format!("artifact store error: {ctx}")
        }
        StoreError::PoolError(_) => {
            "artifact store error: connection pool exhausted; try again in a moment".to_string()
        }
        StoreError::InvalidBlobId(_) => {
            "artifact store error: internal integrity violation (invalid blob id); please file a bug".to_string()
        }
        StoreError::IntegrityError(msg) => {
            format!("artifact store error: integrity check failed: {msg}")
        }
    }
}

fn with_doctor_hint(message: String) -> String {
    format!("{message}\nHint: run 'rv doctor' to diagnose network or TLS issues.")
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_NESTED_ERRORS, redact_url, render_pom_error, render_resolve_error, render_store_error,
    };
    use rv_maven_model::PomError;
    use rv_resolver::{RepoSearchStatus, RepoStatus, ResolveError};
    use rv_store::StoreError;

    // --- URL credential redaction in render_reqwest_error ---

    /// `redact_url` must strip userinfo (user:pass@) from URLs so credentials
    /// never appear in error output.
    #[test]
    fn redact_url_strips_userinfo() {
        let raw = "https://user:secret@repo.example.com/maven/";
        let redacted = redact_url(raw);
        assert!(
            !redacted.contains("secret"),
            "password must not appear: {redacted}"
        );
        assert!(
            !redacted.contains("user:"),
            "userinfo must not appear: {redacted}"
        );
        assert!(
            redacted.contains("repo.example.com"),
            "host must remain: {redacted}"
        );
    }

    /// `redact_url` must replace query-parameter values with `***` so tokens
    /// embedded as `?token=abc` don't leak into error messages.
    #[test]
    fn redact_url_redacts_query_params() {
        let raw = "https://repo.example.com/maven/?token=secret123&api_key=xyz";
        let redacted = redact_url(raw);
        assert!(
            !redacted.contains("secret123"),
            "query value must not appear: {redacted}"
        );
        assert!(
            !redacted.contains("xyz"),
            "api_key value must not appear: {redacted}"
        );
        // Parameter names are preserved for debuggability.
        assert!(
            redacted.contains("token=***"),
            "param name must remain: {redacted}"
        );
        assert!(
            redacted.contains("api_key=***"),
            "param name must remain: {redacted}"
        );
    }

    /// URLs without credentials or query params must pass through unchanged.
    #[test]
    fn redact_url_passes_through_plain_url() {
        let raw = "https://repo1.maven.org/maven2/";
        let redacted = redact_url(raw);
        assert_eq!(redacted, raw);
    }

    /// Non-URL strings (e.g. partial labels) must be returned as-is.
    #[test]
    fn redact_url_returns_non_url_unchanged() {
        let raw = "not a url at all";
        assert_eq!(redact_url(raw), raw);
    }

    // --- Searched: section URL redaction ---

    /// Repository URLs with credentials must not appear verbatim in the
    /// `Searched:` section of `ArtifactNotFound` errors.
    #[test]
    fn artifact_not_found_redacts_repo_url_in_searched_section() {
        let searched = vec![RepoSearchStatus {
            repo_url: "https://user:pass@private.example.com/maven/".to_string(),
            status: RepoStatus::Http(404),
        }];
        let err = ResolveError::ArtifactNotFound {
            coord: "com.example:lib:1.0".to_string(),
            searched,
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

    // --- Store error friendly messages ---

    /// `LockTimeout` must surface its built-in actionable message verbatim
    /// rather than a generic "database error" fallback.
    #[test]
    fn store_error_lock_timeout_surfaces_detailed_message() {
        let err = StoreError::LockTimeout {
            path: std::path::PathBuf::from("/tmp/rv-store/.lock"),
            holder_info: "pid=42 time=1234567890".to_string(),
        };
        let rendered = render_store_error(&err);
        assert!(
            rendered.contains("pid=42"),
            "lock-holder info must be included: {rendered}"
        );
        // Must contain actionable advice: the LockTimeout Display message
        // says "Wait for it to finish" and explicitly warns against deleting.
        assert!(
            rendered.contains("Wait") || rendered.contains("holder"),
            "wait advice must appear: {rendered}"
        );
    }

    /// An I/O error with a disk-full kind must produce a friendly message.
    #[test]
    fn store_error_io_disk_full_produces_friendly_message() {
        let io_err =
            std::io::Error::new(std::io::ErrorKind::StorageFull, "no space left on device");
        let err = StoreError::IoError(io_err);
        let rendered = render_store_error(&err);
        assert!(
            rendered.contains("disk full"),
            "disk-full hint must appear: {rendered}"
        );
        // Must NOT expose rusqlite internals.
        assert!(
            !rendered.contains("SqliteFailure"),
            "rusqlite internal must not appear: {rendered}"
        );
    }

    /// A permission-denied I/O error must produce a friendly message.
    #[test]
    fn store_error_io_permission_denied_produces_friendly_message() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "permission denied");
        let err = StoreError::IoError(io_err);
        let rendered = render_store_error(&err);
        assert!(
            rendered.contains("permission denied"),
            "permission hint must appear: {rendered}"
        );
    }

    #[test]
    fn system_scope_pom_error_renders_focused_suggestions() {
        let err = PomError::InvalidModel(
            "system-scoped dependency com.example:demo requires a non-empty <systemPath>"
                .to_string(),
        );
        let rendered = render_pom_error(&err);
        assert!(
            rendered.starts_with("Local POM error:"),
            "expected focused prefix, got: {rendered}"
        );
        assert!(
            rendered.contains("<systemPath>/absolute/path/to/jar</systemPath>"),
            "missing absolute-path suggestion: {rendered}"
        );
        assert!(
            rendered.contains("system scope is non-portable"),
            "missing portability hint: {rendered}"
        );
        // Misleading "run rv doctor" branch must NOT fire for this case.
        assert!(
            !rendered.contains("rv doctor"),
            "doctor hint must not appear: {rendered}"
        );
    }

    #[test]
    fn non_systempath_invalid_model_still_falls_back_to_doctor_hint() {
        let err = PomError::InvalidModel("model version 5.0.0 is not supported".to_string());
        let rendered = render_pom_error(&err);
        assert!(
            rendered.contains("Invalid POM metadata"),
            "expected generic prefix, got: {rendered}"
        );
        assert!(
            rendered.contains("rv doctor"),
            "doctor hint should remain for non-systemPath errors: {rendered}"
        );
    }

    fn artifact_not_found(coord: &str, searched: Vec<RepoSearchStatus>) -> ResolveError {
        ResolveError::ArtifactNotFound {
            coord: coord.to_string(),
            searched,
        }
    }

    /// Regression: `MultipleArtifactErrors` must render each nested error
    /// recursively rather than fall through to the catch-all
    /// `err.to_string()`. The catch-all drops the per-nested `searched`
    /// repo listing and "add a private repo" suggestion that
    /// `ArtifactNotFound` renders, so the user would lose that context.
    #[test]
    fn multiple_artifact_errors_render_nested_searched_section() {
        let searched = vec![RepoSearchStatus {
            repo_url: "https://repo1.maven.org/maven2/".to_string(),
            status: RepoStatus::Http(404),
        }];
        let err = ResolveError::MultipleArtifactErrors {
            first: Box::new(artifact_not_found(
                "com.example:first:1.0",
                searched.clone(),
            )),
            rest: vec![artifact_not_found(
                "com.example:second:2.0",
                searched.clone(),
            )],
        };
        let rendered = render_resolve_error(&err);
        // Header tells the user how many things failed.
        assert!(
            rendered.contains("2 artifact fetch error(s)"),
            "rendered: {rendered}"
        );
        // Each nested error must surface its own coord.
        assert!(rendered.contains("com.example:first:1.0"));
        assert!(rendered.contains("com.example:second:2.0"));
        // The recursive call must surface the searched repository URL,
        // which the catch-all fall-through path drops.
        assert!(
            rendered.contains("https://repo1.maven.org/maven2/"),
            "searched URL missing: {rendered}"
        );
    }

    /// Output is capped at `MAX_NESTED_ERRORS` plus an "... and N more"
    /// footer to keep the CLI scannable when the entire dep graph fails.
    #[test]
    fn multiple_artifact_errors_render_cap_with_footer() {
        let mut errors: Vec<ResolveError> = (0..(MAX_NESTED_ERRORS + 3))
            .map(|i| artifact_not_found(&format!("g:a{i}:1.0"), vec![]))
            .collect();
        let total = errors.len();
        let first = Box::new(errors.remove(0));
        let err = ResolveError::MultipleArtifactErrors {
            first,
            rest: errors,
        };
        let rendered = render_resolve_error(&err);
        // First MAX_NESTED_ERRORS errors are present...
        for i in 0..MAX_NESTED_ERRORS {
            assert!(
                rendered.contains(&format!("g:a{i}:1.0")),
                "expected nested {i} in output"
            );
        }
        // ...and the rest are suppressed by the cap footer.
        let overflow = total - MAX_NESTED_ERRORS;
        assert!(
            rendered.contains(&format!("... and {overflow} more")),
            "missing cap footer in: {rendered}"
        );
        assert!(!rendered.contains(&format!("g:a{}:1.0", total - 1)));
    }
}
