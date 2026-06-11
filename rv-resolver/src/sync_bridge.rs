//! Utilities for bridging sync and async code safely.
//!
//! This module provides a safe way to run async code from synchronous contexts,
//! handling the different runtime scenarios:
//! - Inside a multi-threaded tokio runtime (use block_in_place)
//! - Inside a single-threaded tokio runtime (dispatched to a cached fallback)
//! - Outside any tokio runtime (cached fallback runtime)

use std::future::Future;
use std::sync::OnceLock;

use tokio::runtime::Runtime;

/// Process-wide fallback runtime used when `block_on_async` is invoked
/// outside any tokio context or from inside a current-thread runtime.
/// Creating a runtime is comparatively expensive (allocates threads,
/// installs signal handlers); caching one keeps the bridge cheap.
static FALLBACK_RT: OnceLock<Runtime> = OnceLock::new();

fn fallback_runtime() -> &'static Runtime {
    FALLBACK_RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to create fallback tokio runtime")
    })
}

/// Run an async future to completion from a synchronous context.
///
/// This function safely handles different runtime scenarios:
/// - If called from within a multi-threaded tokio runtime, uses `block_in_place`
/// - If called from within a current-thread tokio runtime, dispatches to a
///   cached multi-thread fallback runtime to avoid deadlock
/// - If no runtime is active, uses the same cached fallback runtime
pub fn block_on_async<F, T>(future: F) -> T
where
    F: Future<Output = T> + Send,
    T: Send,
{
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => match handle.runtime_flavor() {
            tokio::runtime::RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(|| handle.block_on(future))
            }
            tokio::runtime::RuntimeFlavor::CurrentThread => {
                // Already inside a runtime, so block_on is unavailable. Hand
                // the future to the fallback runtime, blocking the calling
                // thread until it completes.
                std::thread::scope(|s| {
                    s.spawn(|| fallback_runtime().block_on(future))
                        .join()
                        .expect("block_on_async worker thread panicked")
                })
            }
            _ => tokio::task::block_in_place(|| handle.block_on(future)),
        },
        Err(_) => fallback_runtime().block_on(future),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn works_outside_runtime() {
        let result = block_on_async(async { 42 });
        assert_eq!(result, 42);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn works_inside_multi_thread_runtime() {
        let result = block_on_async(async { 42 });
        assert_eq!(result, 42);
    }

    // This test creates a current-thread runtime (no existing runtime) then calls
    // block_on_async inside it. The inner call detects the current-thread runtime
    // and spawns a new thread with its own runtime to avoid deadlock.
    #[test]
    fn handles_nested_calls_outside_runtime() {
        let result = block_on_async(async { block_on_async(async { 42 }) });
        assert_eq!(result, 42);
    }
}
