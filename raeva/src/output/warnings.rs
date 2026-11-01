//! The one warning channel. Library crates raise warnings as
//! `tracing::warn!(sec_code = "...")` events, the CLI adds its own with
//! [`super::Output::warn`], and both land in the [`WarningCollector`] of the
//! run's [`super::Output`]. In `--json` mode they become the envelope's
//! `warnings` array; otherwise they are summarized on stderr at exit.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::Mutex;

use serde_json::Value;

/// Every warning code raeva reports. A library warning names its code as a
/// `sec_code` string, which a unit test checks against this list, so a code
/// cannot reach users without a variant here.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    strum::Display,
    strum::EnumString,
    strum::IntoStaticStr,
    strum::EnumIter,
)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum WarningCode {
    AuthFallback,
    /// A version listing left out a repository that failed, other than with
    /// a 404 or a 401 or 403 refusal, while another repository answered.
    ListingRepoSkipped,
    /// raeva accepted remote metadata under the repository policy although its
    /// checksum still did not match after a retry.
    MetadataChecksumMismatch,
    /// Only a SHA-1 checksum sidecar was available for an artifact.
    WeakHashFallback,
    CrossHostMirror,
    /// The store index or the metadata cache was damaged or not SQLite, so
    /// raeva deleted it and started a new one.
    DatabaseRecreated,
    /// A credential configured for a repository id was not sent to a
    /// repository a fetched POM declared, on an origin neither the
    /// configuration nor the project's POMs name.
    IdCredentialWithheld,
    DefaultCredentialWithheld,
    /// A `<repository>` a fetched parent POM declared was ignored because
    /// it is not an http or https URL.
    FetchedPomRepoRefused,
    /// A `<repository>` a POM declares was ignored because it is plain HTTP
    /// to a host that is not loopback, as Maven's default HTTP blocker does.
    HttpRepoBlocked,
    /// A `<repository>` a POM declares was ignored because its URL has
    /// userinfo, a query or a fragment, which may hold a credential.
    RepoUrlSecretRefused,
    ProjectRepoUrlFromFetchedPom,
    /// A `<repository>` declared by a transitive POM was ignored.
    TransitiveRepoDropped,
    /// The current platform or host JDK is missing from raeva.lock, so the
    /// command used another section from the lock.
    PlatformFallback,
    /// `raeva sync` ran on a host JDK that matches no entry in `[lock] jdks`.
    JdkNotLocked,
    /// A requested profile id that no reactor POM lineage activates and no
    /// settings.xml profile has.
    ProfileNotFound,
    /// A platform the run did not resolve again was left out of the new
    /// raeva.lock because its pins no longer match the project.
    PlatformDropped,
    AdoptRace,
    /// The `cache-key` file beside `metadata.db` could not be read or
    /// written.
    CacheKeyUnavailable,
    /// A metadata cache entry did not match the checksum it was written
    /// with, so raeva dropped it.
    CacheEntryDamaged,
    /// The store's copy of a locked file did not match its raeva.lock checksum,
    /// so the run downloaded the file again.
    StoreFileRefetched,
    /// Credentials were sent over plain HTTP to a host that is not loopback.
    CleartextAuth,
    /// A settings.xml credential was dropped because it could not be
    /// decrypted.
    CredentialDropped,
    /// The project's raeva.toml asked `[security]` to allow more than the
    /// user's config.toml, and raeva ignored that part.
    ProjectSecurityWideningIgnored,
    /// export-m2 ignored `local_repository` in the project's raeva.toml.
    ProjectLocalRepositoryIgnored,
    /// A lockfile field holds the value of a `${env.X}` substitution.
    EnvValueInLockfile,
    /// export-m2 skipped classifier jars whose raeva.lock origin nothing in the
    /// configuration or the project's POMs declares.
    UntrustedClassifierOrigin,
    /// export-m2 skipped a sources or javadoc jar that has no checksum
    /// sidecar.
    ClassifierChecksumMissing,
    /// `export-m2 --offline` skipped a sources or javadoc jar the store does
    /// not hold.
    ClassifierNotStored,
    /// export-m2 did not export system-scoped dependencies.
    ExportSystemScopedSkipped,
    /// export-m2 could not make a copied artifact writable by its owner.
    ExportPermissionsNotSet,
    /// export-m2 wrote into the Maven local repository other builds share,
    /// so it removed no metadata and `mvn -o` there is not a locked build.
    ExportSharedRepository,
    ExportWarning,
    SystemScope,
    LowDiskSpace,
    /// raeva sync replaced a raeva.lock this raeva cannot use.
    LockfileRegenerated,
    /// A remote repository has no checksum file for a download, and the
    /// run accepted that.
    ChecksumMissing,
    /// A POM is invalid, a local parent POM cannot be read, or a dependency
    /// has a scope Maven does not know; raeva went on as Maven does.
    PomProblem,
    /// An environment variable or a configuration entry has a value raeva
    /// cannot use, so raeva went on without it.
    SettingIgnored,
    /// A `--vex` statement applied to no finding or package of the run.
    VexStatementUnused,
    /// A POM read `java.version` without a JDK named by `JAVA_HOME` or
    /// `JAVA_VERSION`, so it saw the stand-in 17.
    JavaVersionDefaulted,
    /// A POM read a set environment variable outside the
    /// `allow_env_substitution` allowlist, which reads as unset.
    EnvVarHidden,
}

impl WarningCode {
    pub(crate) fn as_str(self) -> &'static str {
        self.into()
    }
}

/// Codes sort by their text, so warnings list in the same order whatever
/// order the variants are declared in.
impl Ord for WarningCode {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_str().cmp(other.as_str())
    }
}

impl PartialOrd for WarningCode {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// One warning: a stable code, a message for people, and structured
/// details such as coordinates or URLs (`null` when there are none).
#[derive(Debug, Clone)]
pub(crate) struct Warning {
    pub(crate) code: WarningCode,
    pub(crate) message: String,
    pub(crate) context: Value,
}

impl Warning {
    pub(crate) fn new(code: WarningCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            context: Value::Null,
        }
    }

    pub(crate) fn with_context(mut self, context: Value) -> Self {
        self.context = context;
        self
    }

    pub(crate) fn to_json(&self) -> Value {
        serde_json::json!({
            "code": self.code.as_str(),
            "message": self.message,
            "context": self.context,
        })
    }
}

/// The warnings of one run. How often a condition is observed depends on
/// cache hits and task scheduling, so each distinct warning is kept once and
/// they drain sorted by code, context and message: the same inputs give the
/// same output.
#[derive(Default)]
pub(crate) struct WarningCollector {
    entries: Mutex<BTreeMap<(WarningCode, String, String), Warning>>,
}

impl WarningCollector {
    pub(crate) fn push(&self, warning: Warning) {
        // `serde_json` maps keep sorted keys, so this string is canonical.
        let key = (
            warning.code,
            warning.context.to_string(),
            warning.message.clone(),
        );
        let mut guard = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        guard.entry(key).or_insert(warning);
    }

    /// Drains the collector and returns the distinct warnings in sorted
    /// order.
    pub(crate) fn take(&self) -> Vec<Warning> {
        let mut guard = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let mut entries = std::mem::take(&mut *guard);
        let mut fallbacks = BTreeMap::<_, (Warning, BTreeSet<String>)>::new();
        let mut weak = Vec::new();
        entries.retain(|_, warning| {
            if warning.code == WarningCode::WeakHashFallback {
                weak.push(warning.clone());
                return false;
            }
            if warning.code != WarningCode::AuthFallback {
                return true;
            }
            let context = &warning.context;
            let (Some(refusing), Some(serving), Some(file)) = (
                context["refusing_endpoint"].as_str(),
                context["serving_endpoint"].as_str(),
                context["file"].as_str(),
            ) else {
                return true;
            };
            fallbacks
                .entry((refusing.to_string(), serving.to_string()))
                .or_insert_with(|| (warning.clone(), BTreeSet::new()))
                .1
                .insert(file.to_string());
            false
        });
        for (mut warning, files) in fallbacks.into_values() {
            let context = &warning.context;
            let refusing = context["refusing"].as_str().unwrap_or("unknown");
            let serving = context["serving"].as_str().unwrap_or("unknown");
            let coordinate = context["coordinate"].as_str().unwrap_or("unknown");
            let more = match files.len() {
                0 | 1 => String::new(),
                2 => " (and 1 more file)".to_string(),
                count => format!(" (and {} more files)", count - 1),
            };
            let unset: Vec<String> = context["unset_variables"]
                .as_str()
                .map(|names| names.split(',').map(str::to_string).collect())
                .unwrap_or_default();
            let unset = crate::error::report::unset_variables_note(&unset)
                .map(|note| format!(" {note}."))
                .unwrap_or_default();
            warning.message = format!(
                "Repository `{refusing}` refused {coordinate} (HTTP {}){more}; using the copy from `{serving}`.{unset} Check the credentials for `{refusing}` if the file should come from there.",
                context["status"]
            );
            entries.insert(
                (
                    warning.code,
                    warning.context.to_string(),
                    warning.message.clone(),
                ),
                warning,
            );
        }
        // A repository many POMs declare is one warning that lists them.
        let mut dropped = BTreeMap::<String, (Warning, BTreeSet<String>)>::new();
        entries.retain(|_, warning| {
            let context = &warning.context;
            let (WarningCode::TransitiveRepoDropped, Some(url), Some(declared_by)) = (
                warning.code,
                context["url"].as_str(),
                context["declared_by"].as_str(),
            ) else {
                return true;
            };
            // `.../maven2` and `.../maven2/` name one repository.
            dropped
                .entry(url.trim_end_matches('/').to_string())
                .or_insert_with(|| (warning.clone(), BTreeSet::new()))
                .1
                .insert(declared_by.to_string());
            false
        });
        for (mut warning, declared_by) in dropped.into_values() {
            let url = warning.context["url"].clone();
            warning.context = serde_json::json!({ "url": url, "declared_by": declared_by });
            entries.insert(
                (
                    warning.code,
                    warning.context.to_string(),
                    warning.message.clone(),
                ),
                warning,
            );
        }
        // Old artifacts on Central have no SHA-256, so a cold sync can fall
        // back for thousands of files: one warning counts them.
        if weak.len() > 1 {
            let count = weak.len();
            let path = weak[0].context["path"]
                .as_str()
                .unwrap_or("unknown")
                .to_string();
            let warning = Warning::new(
                WarningCode::WeakHashFallback,
                format!(
                    "{count} files were verified with a SHA-1 or MD5 checksum (weak hash \
                     algorithms), such as {path}; the repositories should provide SHA-256 \
                     checksums"
                ),
            )
            .with_context(serde_json::json!({ "count": count, "path": path }));
            weak = vec![warning];
        }
        for warning in weak {
            entries.insert(
                (
                    warning.code,
                    warning.context.to_string(),
                    warning.message.clone(),
                ),
                warning,
            );
        }
        entries.into_values().collect()
    }
}

/// One line per warning code, except `AUTH_FALLBACK` prints each repository
/// pair, each starting with `warning: `, in code order, from the distinct
/// warnings [`WarningCollector::take`] returns. A
/// code raised once prints its message and context; a code raised for
/// several things prints one line with a count, and `--json` lists each.
/// `list_all` says how to list them, such as `'raeva --json sync' lists
/// them`.
///
/// Two codes are left out, and `--json` keeps both. `WEAK_HASH_FALLBACK` is
/// raised only for files a run downloads, so it would come and go with the
/// state of the store. `TRANSITIVE_REPO_DROPPED` fires on most projects, and
/// a dependency that only such a repository has fails with an error that
/// names it. Neither leaves the user anything to do.
pub(crate) fn summarize(warnings: &[Warning], list_all: &str) -> Vec<String> {
    let mut groups: BTreeMap<WarningCode, Vec<&Warning>> = BTreeMap::new();
    for warning in warnings {
        if !matches!(
            warning.code,
            WarningCode::WeakHashFallback | WarningCode::TransitiveRepoDropped
        ) {
            groups.entry(warning.code).or_default().push(warning);
        }
    }
    groups
        .into_iter()
        .flat_map(|(code, group)| {
            if code == WarningCode::AuthFallback {
                return group
                    .into_iter()
                    .map(|warning| format!("warning: {code}: {}", warning.message))
                    .collect::<Vec<_>>();
            }
            let mut line = describe(group[0]);
            if group.len() > 1 {
                line.push_str(&format!(" and {} more ({list_all})", group.len() - 1));
            }
            vec![format!("warning: {code}: {line}")]
        })
        .collect()
}

fn describe(warning: &Warning) -> String {
    let mut line = warning.message.clone();
    if let Some(context) = warning.context.as_object() {
        let fields: Vec<String> = context
            .iter()
            .map(|(k, v)| match v.as_str() {
                Some(text) => format!("{k}={text}"),
                None => format!("{k}={v}"),
            })
            .collect();
        if !fields.is_empty() {
            line.push_str(&format!(" ({})", fields.join(", ")));
        }
    }
    line
}

/// The `tracing` layer that turns warning events into [`Warning`]s.
///
/// It runs beside the fmt layer with its own `WARN` filter, so it sees the
/// events fmt would print whatever the user-facing log level, also in
/// `--json` mode where fmt is off. An event with a `sec_code` field becomes
/// a warning with that code. A unit test checks that every warning raeva logs
/// has one; a warning from another crate stays in the log.
pub(crate) struct WarningCollectorLayer {
    sink: Box<dyn Fn(Warning) + Send + Sync + 'static>,
    /// Each event already turned into a warning, by callsite and field
    /// values. Each module of a large reactor logs the same warnings again,
    /// thousands of times on some projects, and the sink keeps one of each.
    seen: Mutex<HashSet<(tracing::callsite::Identifier, Vec<u8>)>>,
}

impl WarningCollectorLayer {
    pub(crate) fn new(sink: impl Fn(Warning) + Send + Sync + 'static) -> Self {
        Self {
            sink: Box::new(sink),
            seen: Mutex::default(),
        }
    }
}

impl<S> tracing_subscriber::Layer<S> for WarningCollectorLayer
where
    S: tracing::Subscriber,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        // Only warnings and errors are collected; walking the fields of every
        // info and debug event would cost time on large resolutions.
        if *event.metadata().level() > tracing::Level::WARN {
            return;
        }
        let mut values = FieldValues(Vec::with_capacity(512));
        event.record(&mut values);
        let key = (event.metadata().callsite(), values.0);
        if !(self.seen.lock().unwrap_or_else(|e| e.into_inner())).insert(key) {
            return;
        }
        let mut visitor = SecCodeVisitor::default();
        event.record(&mut visitor);
        // A unit test checks that every code in the sources parses.
        let Some(Ok(code)) = visitor.code.as_deref().map(str::parse::<WarningCode>) else {
            return;
        };
        let message = visitor.message.unwrap_or_else(|| code.to_string());
        let context = if visitor.fields.is_empty() {
            Value::Null
        } else {
            Value::Object(visitor.fields)
        };
        (self.sink)(Warning::new(code, message).with_context(context));
    }
}

/// An event's field values as [`SecCodeVisitor`] reads them, each after its
/// field's index and kind and before its length, so different values never
/// give the same bytes.
struct FieldValues(Vec<u8>);

impl FieldValues {
    fn push(&mut self, field: &tracing::field::Field, kind: u8, value: impl FnOnce(&mut Vec<u8>)) {
        self.0.extend(field.index().to_le_bytes());
        self.0.push(kind);
        let start = self.0.len();
        value(&mut self.0);
        let length = self.0.len() - start;
        self.0.extend(length.to_le_bytes());
    }
}

impl tracing::field::Visit for FieldValues {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.push(field, 0, |out| out.extend(value.as_bytes()));
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.push(field, 1, |out| out.extend(value.to_le_bytes()));
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.push(field, 2, |out| out.extend(value.to_le_bytes()));
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.push(field, 3, |out| out.push(u8::from(value)));
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        use std::io::Write;
        self.push(field, 4, |out| {
            let _ = write!(out, "{value:?}");
        });
    }
}

#[derive(Default)]
struct SecCodeVisitor {
    code: Option<String>,
    message: Option<String>,
    fields: serde_json::Map<String, Value>,
}

impl SecCodeVisitor {
    fn text(&mut self, field: &tracing::field::Field, value: String) {
        match field.name() {
            "sec_code" => self.code = Some(value),
            "message" => self.message = Some(value),
            other => self.value(other, Value::String(value)),
        }
    }

    fn value(&mut self, name: &str, value: Value) {
        self.fields.insert(name.to_string(), value);
    }
}

impl tracing::field::Visit for SecCodeVisitor {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.text(field, value.to_string());
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.value(field.name(), Value::Number(value.into()));
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.value(field.name(), Value::Number(value.into()));
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.value(field.name(), Value::Bool(value));
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        // `%value` and `?value` fields arrive here. A string's `Debug` form
        // is wrapped in one pair of quotes: strip exactly that pair, so a
        // value that itself starts or ends with `"` keeps it.
        let rendered = format!("{value:?}");
        let trimmed = (rendered.strip_prefix('"'))
            .and_then(|inner| inner.strip_suffix('"'))
            .unwrap_or(&rendered);
        self.text(field, trimmed.to_string());
    }
}

#[cfg(test)]
mod tests {
    use strum::IntoEnumIterator;

    use super::WarningCode;

    #[test]
    fn auth_fallback_counts_distinct_files_and_keeps_each_repository_pair() {
        use super::{WarningCollector, WarningCollectorLayer, summarize};
        use tracing_subscriber::layer::SubscriberExt;
        let collector = std::sync::Arc::new(WarningCollector::default());
        let sink = collector.clone();
        let subscriber =
            tracing_subscriber::registry().with(WarningCollectorLayer::new(move |warning| {
                sink.push(warning)
            }));
        rv_test_support::with_default(subscriber, || {
            for (refusing, status, file) in [
                ("corp", 401, "lib.pom"),
                ("corp", 401, "lib.pom"),
                ("corp", 403, "lib.pom"),
                ("corp", 401, "lib.jar"),
                ("other", 403, "lib.jar"),
            ] {
                let mut fallback = rv_repo::AuthFallback::default();
                fallback.refused(
                    &rv_repo::Repository::new(
                        Some(refusing.to_string()),
                        format!("https://{refusing}.example/"),
                        true,
                        false,
                    ),
                    &rv_repo::RepoError::Unauthorized {
                        status: reqwest::StatusCode::from_u16(status).unwrap(),
                        url: "https://private.example/lib".to_string(),
                        sent: (refusing == "corp").then(|| {
                            Box::new(rv_repo::SentCredential {
                                id: Some("corp".to_string()),
                                file: rv_repo::CredentialFile::Settings,
                                unset_variables: vec!["CORP_TOKEN".to_string()],
                            })
                        }),
                    },
                );
                fallback.served(
                    &rv_repo::Repository::new(
                        Some("central".to_string()),
                        "https://public.example/",
                        true,
                        false,
                    ),
                    &rv_repo::ArtifactRequest::new("g", "lib", "1"),
                    file.to_string(),
                );
            }
        });
        let warnings = collector.take();
        assert_eq!(warnings.len(), 2);
        let corp = warnings
            .iter()
            .find(|warning| warning.context["refusing"] == "corp")
            .unwrap();
        let other = warnings
            .iter()
            .find(|warning| warning.context["refusing"] == "other")
            .unwrap();
        assert!(corp.message.contains("and 1 more file"));
        assert!(
            corp.message.contains(
                "`central`. CORP_TOKEN is not set, so the repository received the literal \
                 text ${env.CORP_TOKEN}. Check"
            ),
            "{}",
            corp.message
        );
        assert_eq!(corp.context["unset_variables"], "CORP_TOKEN");
        assert!(!other.message.contains("not set"), "{}", other.message);
        assert!(!other.message.contains("more file"));
        assert_eq!(warnings[0].to_json()["code"], "AUTH_FALLBACK");
        let lines = summarize(&warnings, "'raeva --json sync' lists them");
        assert_eq!(lines.len(), 2);
        assert!(
            lines
                .iter()
                .any(|line| line.contains("`corp`") && line.contains("`central`"))
        );
        assert!(
            lines
                .iter()
                .any(|line| line.contains("`other`") && line.contains("`central`"))
        );
        assert!(collector.take().is_empty());
    }

    #[test]
    fn auth_fallback_groups_by_both_endpoints_and_preserves_other_warnings() {
        use super::{Warning, WarningCollector, summarize};
        let collector = WarningCollector::default();
        for (refusing, serving, file) in [
            ("corp-a", "public-a", "a.pom"),
            ("corp-b", "public-a", "b.pom"),
            ("corp-a", "public-b", "c.pom"),
        ] {
            collector.push(
                Warning::new(WarningCode::AuthFallback, "event").with_context(serde_json::json!({
                    "refusing": "corp", "serving": "central", "refusing_endpoint": refusing,
                    "serving_endpoint": serving, "coordinate": "g:a:1", "status": 401, "file": file,
                })),
            );
        }
        for message in ["z", "a", "a"] {
            collector.push(Warning::new(WarningCode::PomProblem, message));
        }
        let warnings = collector.take();
        assert_eq!(warnings.len(), 5);
        assert!(
            warnings[..3]
                .iter()
                .all(|warning| !warning.message.contains("more file"))
        );
        assert_eq!(warnings[3].message, "a");
        assert_eq!(warnings[4].message, "z");
        assert_eq!(
            warnings[3].to_json()["context"]["file"],
            serde_json::Value::Null
        );
        assert_eq!(
            summarize(&warnings[3..], "'raeva --json sync' lists them"),
            ["warning: POM_PROBLEM: a and 1 more ('raeva --json sync' lists them)"]
        );
    }

    /// A repository that several POMs declare is one warning listing them.
    #[test]
    fn dropped_repositories_are_one_warning_per_url() {
        use super::{Warning, WarningCollector};
        let collector = WarningCollector::default();
        for (url, declared_by) in [
            ("https://a/", "g:y:1"),
            ("https://a", "g:x:1"),
            ("https://b/", "g:x:1"),
        ] {
            collector.push(
                Warning::new(WarningCode::TransitiveRepoDropped, "ignoring")
                    .with_context(serde_json::json!({ "url": url, "declared_by": declared_by })),
            );
        }
        let contexts: Vec<_> = collector.take().into_iter().map(|w| w.context).collect();
        assert_eq!(
            contexts,
            [
                serde_json::json!({ "url": "https://a", "declared_by": ["g:x:1", "g:y:1"] }),
                serde_json::json!({ "url": "https://b/", "declared_by": ["g:x:1"] }),
            ]
        );
    }

    /// One `WEAK_HASH_FALLBACK` counts the files, however many fell back;
    /// a single one keeps its own message.
    #[test]
    fn weak_hash_fallbacks_are_counted_in_one_warning() {
        use super::{Warning, WarningCollector};
        let collector = WarningCollector::default();
        let weak = |path: &str| {
            Warning::new(
                WarningCode::WeakHashFallback,
                "falling back to SHA-1 checksum",
            )
            .with_context(serde_json::json!({ "path": path }))
        };
        collector.push(weak("a/a-1.pom"));
        assert_eq!(
            collector.take()[0].message,
            "falling back to SHA-1 checksum"
        );
        for n in 0..3000 {
            collector.push(weak(&format!("g/a/{n}/a-{n}.jar")));
        }
        collector.push(Warning::new(WarningCode::PomProblem, "other"));
        let warnings = collector.take();
        assert_eq!(warnings.len(), 2, "{warnings:?}");
        let weak = &warnings[1];
        assert_eq!(weak.context["count"], 3000);
        assert_eq!(weak.context["path"], "g/a/0/a-0.jar");
        assert!(
            weak.message.starts_with("3000 files were verified"),
            "{}",
            weak.message
        );
    }

    /// docs/json-output.md names every field `Warning::to_json` prints.
    /// A new key must fail here until the envelope section mentions it.
    #[test]
    fn the_docs_name_every_warning_field() {
        let warning = super::Warning::new(WarningCode::PomProblem, "x")
            .with_context(serde_json::json!({"k": 1}));
        let fields = warning
            .to_json()
            .as_object()
            .expect("warning object")
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        assert!(!fields.is_empty(), "a warning JSON object has no keys");
        let docs = rv_test_support::fixtures::workspace_file("docs/json-output.md");
        let section = rv_test_support::fixtures::markdown_section(&docs, "## The envelope");
        rv_test_support::fixtures::assert_markdown_names(
            section,
            "docs/json-output.md envelope section",
            &fields,
        );
    }

    /// docs/json-output.md lists every warning code once, sorted, and no
    /// code that does not exist.
    #[test]
    fn the_docs_list_exactly_the_warning_codes() {
        let documented = rv_test_support::fixtures::markdown_first_column(
            &rv_test_support::fixtures::workspace_file("docs/json-output.md"),
            "## Warning codes",
        );
        let mut expected: Vec<String> = WarningCode::iter()
            .map(|code| code.as_str().to_string())
            .collect();
        expected.sort();
        assert_eq!(documented, expected, "docs/json-output.md warning table");
    }

    /// Every `warn!` and `error!` outside tests carries a `sec_code`, so it
    /// reaches the `--json` warnings and the summary at exit. A message that
    /// asks nothing of the user belongs at debug level instead.
    #[test]
    fn every_warning_outside_tests_has_a_code() {
        let (mut uncoded, mut scanned) = (Vec::new(), 0);
        for (shown, text) in rv_test_support::fixtures::workspace_production_sources() {
            let body = rv_test_support::fixtures::without_strings_and_comments(
                &rv_test_support::fixtures::without_inline_test_module(&text),
            );
            for (at, _) in rv_test_support::fixtures::rust_macro_calls(
                &body,
                &[concat!("warn", "!"), concat!("error", "!")],
            ) {
                let Some(open_at) = body[at..].find('(').map(|rel| at + rel) else {
                    continue;
                };
                let call_end =
                    rv_test_support::fixtures::matching_close(&body[open_at..], b'(', b')')
                        .map_or(body.len(), |end| open_at + end);
                scanned += 1;
                if !body[at..call_end].contains("sec_code") {
                    let line = body[..at].matches('\n').count() + 1;
                    uncoded.push(format!("{shown}:{line}"));
                }
            }
        }
        assert!(scanned > 0, "the scan found no warnings");
        assert!(
            uncoded.is_empty(),
            "warnings without a sec_code: {uncoded:#?}"
        );
    }
}
