use std::io::{self, IsTerminal};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

use indicatif::{ProgressBar, ProgressStyle};
use owo_colors::OwoColorize;
use rv_repo::FetchProgress;
use url::Url;

const SPINNER_TEMPLATE: &str = "{spinner:.cyan} {msg}";
const SPINNER_TICKS: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const BAR_TEMPLATE: &str = "{spinner:.cyan} {msg} [{bar:20.cyan/blue}] {bytes}/{total_bytes}";
const BAR_PROGRESS_CHARS: &str = "=>-";

static QUIET: AtomicBool = AtomicBool::new(false);
static JSON_MODE: AtomicBool = AtomicBool::new(false);

pub fn set_quiet(value: bool) {
    QUIET.store(value, Ordering::Relaxed);
}

pub fn quiet_enabled() -> bool {
    QUIET.load(Ordering::Relaxed)
}

/// Enable or disable global JSON output mode.
pub fn set_json_mode(value: bool) {
    JSON_MODE.store(value, Ordering::Relaxed);
}

/// Returns `true` when the global `--json` flag is active.
pub fn is_json_mode() -> bool {
    JSON_MODE.load(Ordering::Relaxed)
}

/// Print a structured JSON result envelope to stdout (only when `--json` is active).
///
/// The envelope has the shape
/// `{ "success": bool, ["exit_code": N, "error": "..."], "data": { ..., "warnings": [...] } }`.
/// If the caller's `data` object contains the keys `exit_code` and/or
/// `error`, they are hoisted to the envelope's top level. They are
/// failure metadata, not part of the command payload, and consumers
/// expect them next to `success`. Any warnings collected during the
/// command run via [`warning_collector`] are attached to the `data`
/// object so callers receive them on the same channel as the result.
/// Without this, security/policy warnings raised through
/// `tracing::warn!` would vanish in `--json` mode (the subscriber is
/// installed at level `off`).
///
/// Hoisting and the `warnings` array work for *every* payload kind, not just
/// objects: scalar and array payloads are first wrapped under `value`, so the
/// `data` field is always an object whose `warnings` array consumers can rely
/// on. (A scalar/array payload cannot itself carry `exit_code`/`error` keys,
/// so for those kinds there is nothing to hoist: the top-level fields
/// are omitted rather than silently lost in a non-object shape.)
pub fn json_result(success: bool, data: serde_json::Value) {
    if is_json_mode() {
        let warnings = warning_collector().drain_json();
        let envelope = build_envelope(success, data, warnings);
        println!("{envelope}");
    }
}

/// Assemble the JSON result envelope from a payload and the drained warnings.
///
/// Pure (no I/O, no global state) so the hoisting/normalisation contract can be
/// unit-tested directly. See [`json_result`] for the envelope shape and the
/// rationale behind hoisting `exit_code`/`error` to the top level.
fn build_envelope(
    success: bool,
    data: serde_json::Value,
    warnings: Vec<serde_json::Value>,
) -> serde_json::Value {
    // Normalise the payload to an object first so hoisting and the `warnings`
    // attachment follow one path for all payload kinds. Scalars and arrays are
    // wrapped under `value`; objects pass through.
    let mut map = match data {
        serde_json::Value::Object(map) => map,
        other => {
            let mut wrapper = serde_json::Map::new();
            wrapper.insert("value".to_string(), other);
            wrapper
        }
    };

    // Lift failure metadata to the envelope top level (next to `success`), then
    // always attach a (possibly empty) `warnings` array so consumers can rely
    // on the field shape without probing for its presence.
    let hoisted_exit_code = map.remove("exit_code");
    let hoisted_error = map.remove("error");
    map.insert("warnings".to_string(), serde_json::Value::Array(warnings));

    let mut envelope = serde_json::Map::new();
    envelope.insert("success".to_string(), serde_json::Value::Bool(success));
    if let Some(code) = hoisted_exit_code {
        envelope.insert("exit_code".to_string(), code);
    }
    if let Some(err) = hoisted_error {
        envelope.insert("error".to_string(), err);
    }
    envelope.insert("data".to_string(), serde_json::Value::Object(map));
    serde_json::Value::Object(envelope)
}

/// Structured warning emitted alongside the JSON envelope.
///
/// `code` is a stable machine identifier (see [`warning_collector`] for the
/// catalogue), `message` is human-readable, and `context` carries optional
/// structured details (artifact coordinates, host names, etc.).
#[derive(Debug, Clone)]
pub struct WarningEntry {
    pub code: &'static str,
    pub message: String,
    pub context: serde_json::Value,
}

impl WarningEntry {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            context: serde_json::Value::Null,
        }
    }

    pub fn with_context(mut self, context: serde_json::Value) -> Self {
        self.context = context;
        self
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "code": self.code,
            "message": self.message,
            "context": self.context,
        })
    }
}

/// Process-wide collector for structured warnings.
///
/// Library crates raise warnings through `tracing::warn!`. In JSON mode the
/// tracing subscriber is installed at `off`, so those messages are dropped.
/// CLI sites that detect or surface a warning condition can additionally
/// `push` a [`WarningEntry`] here so it appears in the JSON envelope's
/// `warnings` channel.
///
/// The warning code catalogue lives in [`WARNING_CODE_CATALOGUE`]; extend it
/// as new conditions are surfaced.
pub struct WarningCollector {
    entries: Mutex<Vec<WarningEntry>>,
}

impl WarningCollector {
    const fn new() -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
        }
    }

    pub fn push(&self, entry: WarningEntry) {
        let mut guard = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        guard.push(entry);
    }

    /// Drains the collector and returns the entries serialized as JSON
    /// values, ready to splice into an envelope.
    fn drain_json(&self) -> Vec<serde_json::Value> {
        let mut guard = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let drained = std::mem::take(&mut *guard);
        drained.iter().map(WarningEntry::to_json).collect()
    }
}

/// Returns the global warning collector.
pub fn warning_collector() -> &'static WarningCollector {
    static COLLECTOR: WarningCollector = WarningCollector::new();
    &COLLECTOR
}

/// Catalogue of every `sec_code` the workspace emits, with a one-line
/// description. The catalogue is what lets `WarningCollectorLayer` stamp
/// entries with a `&'static str` code; codes missing from this list collapse
/// to `UNCATALOGUED` in the JSON envelope, so every new
/// `tracing::warn!(sec_code = ...)` site must add its code here.
const WARNING_CODE_CATALOGUE: &[(&str, &str)] = &[
    (
        "WEAK_HASH_FALLBACK",
        "only a weak (SHA-1) checksum sidecar was available; a stronger one could not be obtained",
    ),
    (
        "CROSS_HOST_MIRROR",
        "a mirror rule resolved to a different host than the configured repository, so default credentials were suppressed",
    ),
    (
        "TRANSITIVE_REPO_DROPPED",
        "a <repository> declared by a transitive POM was ignored; rv only honors top-level repository config",
    ),
    (
        "PLATFORM_FALLBACK",
        "the current platform is missing from the lockfile and the CLI fell back to the first available platform",
    ),
    (
        "ADOPT_RACE",
        "a store blob disappeared between its existence check and the index write (concurrent GC); repaired on next sync",
    ),
    (
        "CLEARTEXT_AUTH",
        "credentials were attached to a plaintext HTTP request to a non-loopback host",
    ),
    (
        "CREDENTIAL_DROPPED",
        "settings.xml credential dropped after failed decryption",
    ),
    (
        "KEYRING_UNAVAILABLE",
        "the OS credential store was unavailable, so configured credentials were used",
    ),
    (
        "KEYRING_ENTRY_MISSING",
        "no OS credential entry matched the endpoint, so configured credentials were used",
    ),
    (
        "ENV_VALUE_IN_LOCKFILE",
        "a lockfile field contains the resolved value of a ${env.X} substitution; the secret may have leaked into a tracked artifact",
    ),
    (
        "GC_RACE",
        "a bad blob scheduled for cleanup was already gone (concurrent GC) during checksum-mismatch repair",
    ),
    (
        "MIRROR_SELF_REF",
        "a mirror entry points at the repository it mirrors and was ignored",
    ),
];

/// Look up an emitted `sec_code` in the catalogue, returning the interned
/// `&'static str` code or `UNCATALOGUED` for unknown codes.
fn catalogued_code(code: &str) -> &'static str {
    WARNING_CODE_CATALOGUE
        .iter()
        .find(|(known, _)| *known == code)
        .map(|(known, _)| *known)
        .unwrap_or("UNCATALOGUED")
}

/// `tracing` layer that bridges `tracing::warn!(sec_code = "...", ...)`
/// events into a [`WarningCollector`].
///
/// The library crates emit security/policy warnings through
/// `tracing::warn!`. In `--json` mode the fmt subscriber is installed at
/// level `off`, so those messages vanish. This layer is registered
/// alongside fmt with its own `WARN` filter so it captures the same
/// events that fmt would have printed, independent of the user-facing
/// log level.
///
/// To opt a warn site into the JSON envelope's `warnings` array, attach
/// a `sec_code = "WEAK_HASH_FALLBACK"` (or other catalogued code) field
/// to the event:
///
/// ```ignore
/// tracing::warn!(
///     sec_code = "WEAK_HASH_FALLBACK",
///     path = %artifact_path,
///     "..."
/// );
/// ```
///
/// Events without `sec_code` are ignored by this layer (fmt still prints
/// them when the log level allows).
///
/// The layer holds an `Arc<dyn Fn(WarningEntry)>` sink so production
/// installs forward to the process-wide [`warning_collector`] while
/// tests can plug in a per-test sink without racing on shared state.
pub struct WarningCollectorLayer {
    sink: std::sync::Arc<dyn Fn(WarningEntry) + Send + Sync + 'static>,
}

impl WarningCollectorLayer {
    /// Build a layer that pushes captured events into the process-wide
    /// `WarningCollector` (the production wiring).
    pub fn global() -> Self {
        Self {
            sink: std::sync::Arc::new(|entry| warning_collector().push(entry)),
        }
    }

    #[cfg(test)]
    pub fn with_sink<F>(sink: F) -> Self
    where
        F: Fn(WarningEntry) + Send + Sync + 'static,
    {
        Self {
            sink: std::sync::Arc::new(sink),
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
        // Cheap fast path: only inspect `WARN`-level events. The library
        // crates emit `info!`/`debug!` at high volume; walking every
        // event's field set would add measurable overhead.
        if *event.metadata().level() != tracing::Level::WARN {
            return;
        }
        let mut visitor = SecCodeVisitor::default();
        event.record(&mut visitor);
        let Some(code) = visitor.code else {
            return;
        };
        let message = visitor.message.unwrap_or_else(|| code.to_string());
        // Translate the catalogue code string into a `&'static str` so
        // `WarningEntry::new` can stamp the entry without an allocation
        // per call site. Unknown codes degrade gracefully to a generic
        // bucket so the envelope still surfaces the message.
        let static_code = catalogued_code(&code);
        let context = if visitor.fields.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::Value::Object(visitor.fields)
        };
        (self.sink)(WarningEntry::new(static_code, message).with_context(context));
    }
}

#[derive(Default)]
struct SecCodeVisitor {
    code: Option<String>,
    message: Option<String>,
    fields: serde_json::Map<String, serde_json::Value>,
}

impl tracing::field::Visit for SecCodeVisitor {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        match field.name() {
            "sec_code" => self.code = Some(value.to_string()),
            "message" => self.message = Some(value.to_string()),
            other => {
                self.fields.insert(
                    other.to_string(),
                    serde_json::Value::String(value.to_string()),
                );
            }
        }
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.fields.insert(
            field.name().to_string(),
            serde_json::Value::Number(value.into()),
        );
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.fields.insert(
            field.name().to_string(),
            serde_json::Value::Number(value.into()),
        );
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.fields
            .insert(field.name().to_string(), serde_json::Value::Bool(value));
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        // Render `Debug`/`Display` payloads (e.g. `%url`, `?coord`) as
        // strings since the JSON envelope schema treats `context` as a
        // free-form map. `tracing` routes `%foo`/`?foo` through this
        // visitor method. String `Debug` wraps in a single pair of
        // quotes; strip exactly one leading and one trailing quote, not
        // all of them, which would truncate values that legitimately
        // start or end with `"`.
        let rendered = format!("{value:?}");
        let trimmed = strip_one_quote_pair(&rendered).to_string();
        match field.name() {
            "sec_code" => self.code = Some(trimmed),
            "message" => self.message = Some(trimmed),
            other => {
                self.fields
                    .insert(other.to_string(), serde_json::Value::String(trimmed));
            }
        }
    }
}

fn strip_one_quote_pair(s: &str) -> &str {
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

/// True when the stderr stream should receive ANSI color escapes.
pub fn stderr_supports_color() -> bool {
    static CACHE: OnceLock<bool> = OnceLock::new();
    *CACHE.get_or_init(|| {
        if std::env::var_os("NO_COLOR").is_some() {
            return false;
        }
        io::stderr().is_terminal()
    })
}

pub fn success(text: impl AsRef<str>) -> String {
    let text = text.as_ref();
    if stderr_supports_color() {
        text.green().to_string()
    } else {
        text.to_string()
    }
}

pub fn warning(text: impl AsRef<str>) -> String {
    let text = text.as_ref();
    if stderr_supports_color() {
        text.yellow().to_string()
    } else {
        text.to_string()
    }
}

pub fn heading(text: impl AsRef<str>) -> String {
    let text = text.as_ref();
    if stderr_supports_color() {
        text.bold().to_string()
    } else {
        text.to_string()
    }
}

/// Print a user-facing error. Always written to stderr. `--quiet` suppresses
/// spinners and progress but still lets errors through, so CI wrappers always
/// see the reason a non-zero exit happened.
pub fn error(message: impl AsRef<str>) {
    let symbol = if stderr_supports_color() {
        "✗".red().to_string()
    } else {
        "✗".to_string()
    };
    eprintln!("{} {}", symbol, message.as_ref());
}

pub fn action(label: &str, detail: impl AsRef<str>) {
    if !quiet_enabled() {
        // 12-char width keeps "Resolving"/"Downloading"/"Downloaded" aligned.
        let padded = format!("{:<12}", label);
        let styled_label = if stderr_supports_color() {
            padded.cyan().to_string()
        } else {
            padded
        };
        eprintln!("{} {}", styled_label, detail.as_ref());
    }
}

pub fn result(label: &str, detail: impl AsRef<str>) {
    if !quiet_enabled() {
        let padded = format!("{:<12}", label);
        let styled_label = if stderr_supports_color() {
            padded.green().to_string()
        } else {
            padded
        };
        eprintln!("{} {}", styled_label, detail.as_ref());
    }
}

pub struct Spinner {
    bar: ProgressBar,
    label: String,
}

impl Spinner {
    pub fn start(label: impl Into<String>) -> Self {
        let label = label.into();
        let enabled = io::stderr().is_terminal() && !quiet_enabled();
        let bar = if enabled {
            let pb = ProgressBar::new_spinner();
            pb.set_style(
                ProgressStyle::default_spinner()
                    .tick_strings(SPINNER_TICKS)
                    .template(SPINNER_TEMPLATE)
                    .expect("valid template"),
            );
            pb.set_message(label.clone());
            pb.enable_steady_tick(std::time::Duration::from_millis(100));
            pb
        } else {
            ProgressBar::hidden()
        };
        Self { bar, label }
    }

    pub fn finish(self, message: impl AsRef<str>) {
        let elapsed = self.bar.elapsed();
        let suffix = format!("{} ({:.2}s)", message.as_ref(), elapsed.as_secs_f32());
        self.bar.finish_and_clear();
        if !quiet_enabled() {
            eprintln!("{}: {}", self.label, suffix);
        }
    }
}

pub struct ProgressReporter {
    state: Mutex<ProgressState>,
}

struct ProgressState {
    bar: ProgressBar,
}

impl ProgressReporter {
    pub fn new() -> Self {
        let enabled = io::stderr().is_terminal() && !quiet_enabled();
        let bar = if enabled {
            let pb = ProgressBar::new(0);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template(BAR_TEMPLATE)
                    .expect("valid template")
                    .progress_chars(BAR_PROGRESS_CHARS),
            );
            pb
        } else {
            ProgressBar::hidden()
        };
        Self {
            state: Mutex::new(ProgressState { bar }),
        }
    }
}

impl Default for ProgressReporter {
    fn default() -> Self {
        Self::new()
    }
}

impl FetchProgress for ProgressReporter {
    fn on_start(&self, url: &Url, total: Option<u64>) {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.bar.set_length(total.unwrap_or(0));
        state.bar.set_position(0);
        state.bar.set_message(trim_url(url.as_str()));
    }

    fn on_chunk(&self, bytes: usize) {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.bar.inc(bytes as u64);
    }

    fn on_finish(&self, _url: &Url, _total: usize) {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.bar.finish_and_clear();
    }
}

pub struct Table {
    headers: Vec<String>,
    rows: Vec<Vec<String>>,
}

impl Table {
    pub fn new<I, S>(headers: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            headers: headers.into_iter().map(Into::into).collect(),
            rows: Vec::new(),
        }
    }

    pub fn add_row<I, S>(&mut self, row: I)
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.rows.push(row.into_iter().map(Into::into).collect());
    }

    pub fn render(&self) -> String {
        use tabled::builder::Builder;
        use tabled::settings::Style;

        let mut builder = Builder::default();

        if !self.headers.is_empty() {
            builder.push_record(&self.headers);
        }

        for row in &self.rows {
            builder.push_record(row);
        }

        let mut table = builder.build();
        table.with(Style::blank());

        table.to_string()
    }
}

fn trim_url(url: &str) -> String {
    let trimmed = url.trim();
    // Byte fast-path: ASCII URLs (the common case) have len == char count,
    // so anything <=64 bytes is also <=64 chars and needs no walk.
    if trimmed.len() <= 64 {
        return trimmed.to_string();
    }
    if trimmed.chars().count() <= 64 {
        return trimmed.to_string();
    }
    let chars: Vec<char> = trimmed.chars().collect();
    let start: String = chars.iter().take(32).collect();
    let end: String = chars.iter().skip(chars.len() - 28).collect();
    format!("{start}...{end}")
}

#[cfg(test)]
mod tests {
    use super::{Table, WarningCollector, WarningEntry, build_envelope, strip_one_quote_pair};

    /// An object payload must have its `exit_code`/`error` keys hoisted to the
    /// envelope top level and a `warnings` array attached to `data`.
    #[test]
    fn build_envelope_hoists_failure_metadata_from_object() {
        let data = serde_json::json!({
            "verified": 1,
            "exit_code": 7,
            "error": "1 missing, 0 corrupt",
        });
        let env = build_envelope(false, data, Vec::new());
        assert_eq!(env["success"], serde_json::json!(false));
        assert_eq!(env["exit_code"], serde_json::json!(7));
        assert_eq!(env["error"], serde_json::json!("1 missing, 0 corrupt"));
        // Hoisted keys are removed from data, payload fields remain.
        assert_eq!(env["data"]["verified"], serde_json::json!(1));
        assert!(env["data"].get("exit_code").is_none());
        assert!(env["data"].get("error").is_none());
        // A (possibly empty) warnings array is always present.
        assert_eq!(env["data"]["warnings"], serde_json::json!([]));
    }

    /// A *scalar* payload must still produce a well-formed envelope,
    /// wrapped under `data.value` with a `warnings` array, rather than
    /// dropping the warnings/shape because it isn't an object.
    #[test]
    fn build_envelope_wraps_scalar_payload_and_keeps_warnings() {
        let warnings = vec![serde_json::json!({"code": "WEAK_HASH_FALLBACK"})];
        let env = build_envelope(true, serde_json::json!("just-a-string"), warnings);
        assert_eq!(env["success"], serde_json::json!(true));
        assert_eq!(env["data"]["value"], serde_json::json!("just-a-string"));
        assert_eq!(
            env["data"]["warnings"][0]["code"],
            serde_json::json!("WEAK_HASH_FALLBACK")
        );
        // No failure metadata to hoist from a scalar.
        assert!(env.get("exit_code").is_none());
        assert!(env.get("error").is_none());
    }

    /// An *array* payload is likewise wrapped under `data.value` with
    /// a `warnings` array, instead of losing the predictable envelope shape.
    #[test]
    fn build_envelope_wraps_array_payload() {
        let env = build_envelope(true, serde_json::json!([1, 2, 3]), Vec::new());
        assert_eq!(env["data"]["value"], serde_json::json!([1, 2, 3]));
        assert_eq!(env["data"]["warnings"], serde_json::json!([]));
    }

    #[test]
    fn strip_one_quote_pair_preserves_embedded_quotes() {
        // A genuine leading or trailing `"` in the value must survive
        // round-tripping through `record_debug`.
        assert_eq!(strip_one_quote_pair("\"hello\""), "hello");
        assert_eq!(strip_one_quote_pair("\"\"quoted\"\""), "\"quoted\"");
        assert_eq!(strip_one_quote_pair("no-quotes"), "no-quotes");
        assert_eq!(strip_one_quote_pair("\""), "\"");
        assert_eq!(strip_one_quote_pair(""), "");
    }

    /// Every `sec_code` emitted by the workspace must resolve to itself, not
    /// to `UNCATALOGUED`. This is the known emission list as of writing; new
    /// `tracing::warn!(sec_code = ...)` sites must extend both the catalogue
    /// and this list.
    #[test]
    fn all_emitted_sec_codes_are_catalogued() {
        let emitted = [
            "WEAK_HASH_FALLBACK",
            "CROSS_HOST_MIRROR",
            "TRANSITIVE_REPO_DROPPED",
            "PLATFORM_FALLBACK",
            "ADOPT_RACE",
            "CLEARTEXT_AUTH",
            "CREDENTIAL_DROPPED",
            "ENV_VALUE_IN_LOCKFILE",
            "GC_RACE",
            "MIRROR_SELF_REF",
        ];
        for code in emitted {
            assert_eq!(
                super::catalogued_code(code),
                code,
                "emitted sec_code {code} must be catalogued"
            );
        }
        assert_eq!(super::catalogued_code("NOT_A_REAL_CODE"), "UNCATALOGUED");
    }

    /// Catalogue entries carry a non-empty description and unique codes.
    #[test]
    fn catalogue_entries_are_well_formed() {
        let mut seen = std::collections::HashSet::new();
        for (code, description) in super::WARNING_CODE_CATALOGUE {
            assert!(!description.trim().is_empty(), "{code} needs a description");
            assert!(seen.insert(*code), "duplicate catalogue code {code}");
        }
    }

    #[test]
    fn table_renders_headers() {
        let mut table = Table::new(["col1", "col2"]);
        table.add_row(["a", "b"]);
        let rendered = table.render();
        assert!(rendered.contains("col1"));
        assert!(rendered.contains("a"));
    }

    #[test]
    fn warning_collector_drain_serializes_entries() {
        // Use a local collector to keep the test independent of the
        // process-wide singleton (which other unit tests in the binary
        // could also be feeding).
        let collector = WarningCollector::new();
        collector.push(
            WarningEntry::new("WEAK_HASH_FALLBACK", "fell back to sha1")
                .with_context(serde_json::json!({"coord": "g:a:1"})),
        );
        collector.push(WarningEntry::new("CROSS_HOST_MIRROR", "suppressed auth"));

        let drained = collector.drain_json();
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0]["code"], "WEAK_HASH_FALLBACK");
        assert_eq!(drained[0]["context"]["coord"], "g:a:1");
        assert_eq!(drained[1]["code"], "CROSS_HOST_MIRROR");

        // Second drain returns nothing; entries are consumed.
        let empty = collector.drain_json();
        assert!(empty.is_empty());
    }

    /// `tracing::warn!(sec_code = "...", ...)` must be captured into
    /// the `WarningCollector` by `WarningCollectorLayer`, independent of
    /// the user-facing fmt subscriber's level. We use a per-test sink so
    /// parallel tests cannot race on shared state.
    #[test]
    fn warning_collector_layer_captures_sec_code_events() {
        use std::sync::{Arc, Mutex};
        use tracing_subscriber::Layer;
        use tracing_subscriber::filter::LevelFilter;
        use tracing_subscriber::layer::SubscriberExt;

        let sink: Arc<Mutex<Vec<WarningEntry>>> = Arc::new(Mutex::new(Vec::new()));
        let sink_clone = Arc::clone(&sink);
        let layer = super::WarningCollectorLayer::with_sink(move |entry| {
            let mut guard = sink_clone.lock().unwrap_or_else(|e| e.into_inner());
            guard.push(entry);
        })
        .with_filter(LevelFilter::WARN);

        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            tracing::warn!(
                sec_code = "WEAK_HASH_FALLBACK",
                path = "com/example/lib-1.0.jar",
                "falling back to sha1"
            );
            tracing::warn!(
                sec_code = "CROSS_HOST_MIRROR",
                repo_url = "https://mirror.example/",
                "cross host mirror"
            );
            // An untagged warn must NOT be captured.
            tracing::warn!("operator chatter without sec_code");
        });

        let captured = sink.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(captured.len(), 2, "tagged warns must be captured");
        assert_eq!(captured[0].code, "WEAK_HASH_FALLBACK");
        assert!(
            captured[0].message.contains("falling back"),
            "captured message preserved, got {:?}",
            captured[0].message
        );
        assert_eq!(captured[1].code, "CROSS_HOST_MIRROR");
    }

    /// `info!`/`debug!`/`trace!` events with `sec_code` are intentionally
    /// ignored: the catalogue is for `WARN`-level security/policy
    /// surfaces only, and the level filter is what guarantees we don't
    /// pay the field-visit cost on every info event.
    #[test]
    fn warning_collector_layer_ignores_non_warn_levels() {
        use std::sync::{Arc, Mutex};
        use tracing_subscriber::Layer;
        use tracing_subscriber::filter::LevelFilter;
        use tracing_subscriber::layer::SubscriberExt;

        let sink: Arc<Mutex<Vec<WarningEntry>>> = Arc::new(Mutex::new(Vec::new()));
        let sink_clone = Arc::clone(&sink);
        let layer = super::WarningCollectorLayer::with_sink(move |entry| {
            let mut guard = sink_clone.lock().unwrap_or_else(|e| e.into_inner());
            guard.push(entry);
        })
        .with_filter(LevelFilter::TRACE);

        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(sec_code = "WEAK_HASH_FALLBACK", "should be skipped");
            tracing::debug!(sec_code = "WEAK_HASH_FALLBACK", "should be skipped too");
        });

        let captured = sink.lock().unwrap_or_else(|e| e.into_inner());
        assert!(
            captured.is_empty(),
            "non-warn levels must not be captured, got {captured:?}"
        );
    }
}
