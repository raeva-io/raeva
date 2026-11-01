//! `with_default` captures events from callsites first hit without a
//! subscriber, and only inside its scope.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tracing::span::{Attributes, Id, Record};

/// Counts the WARN events it receives.
#[derive(Clone, Default)]
struct Count(Arc<AtomicUsize>);

impl tracing::Subscriber for Count {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        *metadata.level() == tracing::Level::WARN
    }

    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }

    fn event(&self, _: &tracing::Event<'_>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }

    fn record(&self, _: &Id, _: &Record<'_>) {}
    fn record_follows_from(&self, _: &Id, _: &Id) {}
    fn enter(&self, _: &Id) {}
    fn exit(&self, _: &Id) {}
}

fn warn() {
    tracing::warn!("warning");
}

// Its own integration-test process: another test installing a subscriber
// first could mask the single-dispatcher bug.
#[test]
fn captures_cold_callsites_inside_the_scope_only() {
    let count = Count::default();
    rv_test_support::with_default(count.clone(), || {
        // The callsite registers first on a thread without a subscriber.
        std::thread::spawn(warn).join().unwrap();
        warn();
        tracing::info!("filtered out");
    });
    warn();
    assert_eq!(count.0.load(Ordering::SeqCst), 1);
}
