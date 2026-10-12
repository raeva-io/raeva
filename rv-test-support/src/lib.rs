//! Shared infrastructure for workspace tests; use only as a dev-dependency.

pub mod http;

use std::sync::OnceLock;
use tracing::Dispatch;
use tracing::subscriber::{DefaultGuard, NoSubscriber};

/// Install a thread-local subscriber without losing events to callsite races.
///
/// tracing-core's single-dispatcher fast path initializes process-wide callsite
/// interest from the registering thread's default. A thread without a subscriber
/// can cache `Interest::never()` while another captures that callsite.
/// Serializing captures cannot prevent uncaptured tests from registering callsites.
///
/// Retain two inert dispatchers for the process lifetime so registration always
/// consults all live subscribers. Neither is installed as a default or receives
/// events. Actual capture and filtering remain scoped to the calling thread.
pub fn set_default(subscriber: impl tracing::Subscriber + Send + Sync + 'static) -> DefaultGuard {
    static DISPATCHERS: OnceLock<[Dispatch; 2]> = OnceLock::new();
    DISPATCHERS.get_or_init(|| {
        [
            Dispatch::new(NoSubscriber::default()),
            Dispatch::new(NoSubscriber::default()),
        ]
    });
    tracing::subscriber::set_default(subscriber)
}

/// Run a synchronous body with a deterministic thread-local subscriber.
pub fn with_default<T>(
    subscriber: impl tracing::Subscriber + Send + Sync + 'static,
    body: impl FnOnce() -> T,
) -> T {
    let _guard = set_default(subscriber);
    body()
}
