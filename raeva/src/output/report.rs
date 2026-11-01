//! What a command hands back to be printed, and the JSON envelope.

use std::io;

use serde_json::{Map, Value};

use super::human::Human;
use super::warnings::Warning;
use crate::error::{CliError, Diagnostic};

pub(crate) trait CommandOutput: Send {
    fn to_json(&self) -> serde_json::Result<Value>;

    fn render_human(&self, human: &mut Human<'_>) -> io::Result<()>;
}

/// What a command returns: its output, and the error it ended with when the
/// output is a report of a failure, such as `raeva lock verify` finding
/// missing artifacts.
pub(crate) struct Report {
    pub(super) body: Body,
    pub(super) failure: Option<CliError>,
}

impl std::fmt::Debug for Report {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Report")
            .field("failure", &self.failure)
            .finish_non_exhaustive()
    }
}

pub(super) enum Body {
    /// An envelope's `data` in JSON mode, text otherwise.
    Data(Box<dyn CommandOutput>),
    /// A document that is the command's whole stdout, such as an SBOM or a
    /// SARIF log. It has no place for warnings or an error, so those go to
    /// stderr as text in every mode.
    Document(String),
    /// Nothing to print, as for an error that ended the command.
    Empty,
}

impl Report {
    pub(crate) fn data(output: impl CommandOutput + 'static) -> Self {
        Self {
            body: Body::Data(Box::new(output)),
            failure: None,
        }
    }

    pub(crate) fn document(text: String) -> Self {
        Self {
            body: Body::Document(text),
            failure: None,
        }
    }

    /// The command's output stands, but the command failed with `error`:
    /// the exit status, the envelope's `error`, `code` and `hints`, and the
    /// last line of text output come from it.
    pub(crate) fn failed(mut self, error: CliError) -> Self {
        self.failure = Some(error);
        self
    }

    pub(crate) fn failure_mut(&mut self) -> Option<&mut CliError> {
        self.failure.as_mut()
    }

    pub(super) fn error(error: CliError) -> Self {
        Self {
            body: Body::Empty,
            failure: Some(error),
        }
    }
}

/// The envelope every `--json` run prints:
/// `{"success": bool, "data": {..., "warnings": [...]}}`, and for a failure
/// also `exit_code`, `error`, `code` and `hints` next to `success`.
pub(super) fn envelope(
    data: Option<Map<String, Value>>,
    failure: Option<&Diagnostic>,
    warnings: &[Warning],
) -> Value {
    let mut data = data.unwrap_or_default();
    debug_assert!(!data.contains_key("warnings"), "payload names warnings");
    data.insert(
        "warnings".to_string(),
        Value::Array(warnings.iter().map(Warning::to_json).collect()),
    );
    let mut envelope = Map::new();
    envelope.insert("success".to_string(), Value::Bool(failure.is_none()));
    if let Some(diagnostic) = failure {
        envelope.insert(
            "exit_code".to_string(),
            Value::from(diagnostic.status.code()),
        );
        envelope.insert(
            "error".to_string(),
            Value::from(diagnostic.message.trim_end()),
        );
        envelope.insert("code".to_string(), Value::from(diagnostic.code));
        envelope.insert(
            "hints".to_string(),
            Value::from(
                diagnostic
                    .hints
                    .iter()
                    .map(|hint| hint.trim())
                    .collect::<Vec<_>>(),
            ),
        );
        if let Some(location) = &diagnostic.location {
            envelope.insert(
                "location".to_string(),
                serde_json::json!({"module": location.module, "via": location.via}),
            );
        }
    }
    envelope.insert("data".to_string(), Value::Object(data));
    Value::Object(envelope)
}

#[cfg(test)]
mod tests {

    /// Commands hand their output to the run's `Output` as a report, so
    /// `--json`, `--quiet`, escaping and the progress bars apply to all of
    /// it. A print macro in a command bypasses all four. `main.rs` may print
    /// startup failures; the output layer may print the report.
    #[test]
    fn commands_do_not_print_directly() {
        let src = rv_test_support::fixtures::workspace_root().join("raeva/src");
        rv_test_support::fixtures::assert_children(
            &src,
            &["commands", "error", "output"],
            &[
                "dispatch.rs",
                "error.rs",
                "main.rs",
                "output.rs",
                "session.rs",
            ],
        );
        let may_print =
            |rel: &str| rel == "main.rs" || rel == "output.rs" || rel.starts_with("output/");
        for (shown, text) in rv_test_support::fixtures::workspace_production_sources() {
            let Some(rel) = shown.strip_prefix("raeva/src/") else {
                continue;
            };
            if may_print(rel) {
                continue;
            }
            let body = rv_test_support::fixtures::without_strings_and_comments(
                &rv_test_support::fixtures::without_inline_test_module(&text),
            );
            if let Some(&(at, name)) = rv_test_support::fixtures::rust_macro_calls(
                &body,
                &[
                    concat!("println", "!"),
                    concat!("eprintln", "!"),
                    concat!("print", "!"),
                    concat!("eprint", "!"),
                    concat!("dbg", "!"),
                ],
            )
            .first()
            {
                let line = body[..at].matches('\n').count() + 1;
                panic!("{shown}:{line}: {name}( in a command; return it in the Report");
            }
        }
    }

    /// docs/json-output.md names every envelope field `envelope` inserts.
    /// A new key must fail here until that section mentions it. The test
    /// module is excluded so an `insert` in a test is not a field.
    #[test]
    fn the_docs_name_every_envelope_field() {
        let source =
            rv_test_support::fixtures::without_inline_test_module(include_str!("report.rs"));
        let mut fields: Vec<String> =
            rv_test_support::fixtures::quoted_after(&source, concat!("insert", "("));
        fields.sort();
        fields.dedup();
        assert!(
            !fields.is_empty(),
            "envelope must insert at least one field"
        );
        let docs = rv_test_support::fixtures::workspace_file("docs/json-output.md");
        let section = rv_test_support::fixtures::markdown_section(&docs, "## The envelope");
        for field in fields {
            let named = rv_test_support::fixtures::markdown_names(section, &field)
                || rv_test_support::fixtures::markdown_names(section, &format!("data.{field}"));
            assert!(
                named,
                "docs/json-output.md envelope section must name `{field}` in backticks"
            );
        }
    }
}
