use std::sync::{Arc, Barrier, Mutex};
use tracing::field::{Field, Visit};

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<String>>>);

impl tracing::Subscriber for Capture {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        *metadata.level() == tracing::Level::WARN
    }

    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        struct Message(String);
        impl Visit for Message {
            fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
                if field.name() == "message" {
                    self.0 = format!("{value:?}");
                }
            }
        }
        let mut message = Message(String::new());
        event.record(&mut message);
        self.0.lock().unwrap().push(message.0);
    }
}

fn warn(message: &str) {
    tracing::warn!("{message}");
}

// Keep the cold-callsite scenario in its own integration-test process: another
// test installing a subscriber first could mask the single-dispatcher bug.
#[test]
fn captures_cold_callsites_and_isolates_scopes() {
    let capture = Capture::default();
    rv_test_support::with_default(capture.clone(), || {
        // Register without a subscriber first to test cached callsite interest.
        std::thread::spawn(|| warn("outside capture"))
            .join()
            .unwrap();
        warn("corp");
        tracing::info!("filtered out");
    });
    assert_eq!(*capture.0.lock().unwrap(), ["corp"]);
    warn("after capture");
    assert_eq!(*capture.0.lock().unwrap(), ["corp"]);

    // Captures can overlap without mixing events or serializing test bodies.
    let barrier = Arc::new(Barrier::new(4));
    let threads: Vec<_> = (0..4)
        .map(|worker| {
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let capture = Capture::default();
                let message = format!("worker {worker}");
                rv_test_support::with_default(capture.clone(), || {
                    barrier.wait();
                    for _ in 0..100 {
                        warn(&message);
                    }
                    barrier.wait();
                });
                assert_eq!(*capture.0.lock().unwrap(), vec![message; 100]);
            })
        })
        .collect();
    for thread in threads {
        thread.join().unwrap();
    }

    // Dropping a nested guard, including during unwinding, restores its parent.
    let outer = Capture::default();
    let inner = Capture::default();
    rv_test_support::with_default(outer.clone(), || {
        warn("before");
        assert!(
            std::panic::catch_unwind(|| {
                rv_test_support::with_default(inner.clone(), || {
                    warn("inner");
                    panic!("exercise guard cleanup");
                });
            })
            .is_err()
        );
        warn("after");
    });
    assert_eq!(*outer.0.lock().unwrap(), ["before", "after"]);
    assert_eq!(*inner.0.lock().unwrap(), ["inner"]);
}
