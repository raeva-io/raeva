//! Captures WARN events in tests. rv-config has no tracing-subscriber
//! dev-dependency, and the tests need only the `sec_code` field and the
//! message of WARN events on the current thread.

use std::sync::{Arc, Mutex};

use tracing::field::{Field, Visit};

/// A WARN event: its `sec_code` and `key`, if any, and its message.
#[derive(Debug, Clone, Default)]
pub(crate) struct Warning {
    pub(crate) sec_code: Option<String>,
    pub(crate) key: Option<String>,
    pub(crate) message: String,
}

impl Visit for Warning {
    fn record_str(&mut self, field: &Field, value: &str) {
        match field.name() {
            "sec_code" => self.sec_code = Some(value.to_string()),
            "key" => self.key = Some(value.to_string()),
            "message" => self.message = value.to_string(),
            _ => {}
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        let value = format!("{value:?}");
        match field.name() {
            "sec_code" => self.sec_code = Some(value.trim_matches('"').to_string()),
            "message" => self.message = value,
            _ => {}
        }
    }
}

struct Collector {
    warnings: Arc<Mutex<Vec<Warning>>>,
}

impl tracing::Subscriber for Collector {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        *metadata.level() == tracing::Level::WARN
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        let mut warning = Warning::default();
        event.record(&mut warning);
        self.warnings.lock().unwrap().push(warning);
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

/// Runs `body` and returns its result with the WARN events it emitted.
pub(crate) fn capture_warnings<T>(body: impl FnOnce() -> T) -> (T, Vec<Warning>) {
    let warnings = Arc::new(Mutex::new(Vec::new()));
    let collector = Collector {
        warnings: Arc::clone(&warnings),
    };
    let result = rv_test_support::with_default(collector, body);
    let warnings = warnings.lock().unwrap().clone();
    (result, warnings)
}
