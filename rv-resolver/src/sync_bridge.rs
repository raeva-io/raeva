//! Utilities for bridging sync and async code safely.
//!
//! The model layer (`rv_maven_model::ParentResolver`) is synchronous, so
//! parent-POM and BOM-import resolution has to reach back into async fetch
//! code from a `&self` method that cannot `.await`. [`block_on_async`] is that
//! bridge: it runs a future to completion while blocking the calling thread.
//!
//! # Why the future is never driven on the calling thread
//!
//! The obvious implementation — `block_in_place(|| handle.block_on(future))` —
//! deadlocks, and did (release-blocking hang in reactor `rv sync`).
//!
//! `Handle::block_on` drives the future with tokio's `CachedParkThread`, whose
//! park/unpark token lives in a **thread-local** shared by every `block_on` on
//! that thread — including the outer `Runtime::block_on` that is driving the
//! caller's own task. Waking the outer task only sets that one token. So if
//! anything wakes the outer task while this thread sits inside the nested
//! `block_on`, the nested `park()` consumes the token, the nested future
//! finishes, and the outer `block_on` then parks on an already-spent
//! notification: the outer task is never polled again and the whole process
//! goes idle forever with no timer, no error, and no CPU burn.
//!
//! In an all-reactor `rv sync` the outer task holds the entire
//! `buffer_unordered` fan-out of module resolutions, so one stolen wakeup
//! strands every in-flight module at once.
//!
//! The fix is structural: the future is always handed to a **task on some
//! runtime**, and this thread waits on an ordinary `std::sync::mpsc` channel.
//! `std::sync::mpsc` has its own condvar and never touches tokio's per-thread
//! park token, so no wakeup can be stolen from the caller's task.

use std::any::Any;
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::sync::OnceLock;
use std::sync::mpsc;

use futures::FutureExt;
use tokio::runtime::{Handle, Runtime, RuntimeFlavor};

/// The payload a panicking bridged future produced, carried back to the
/// calling thread so it can be re-raised unchanged.
type PanicPayload = Box<dyn Any + Send>;

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

/// Spawn `future` on `handle` and return the receiving end of its outcome.
///
/// The outcome is a `Result` because the channel is the only path back to the
/// caller: a panicking task would otherwise drop the sender and leave the
/// caller with nothing but a closed channel, losing the payload, the message
/// and the panic location. Catching here keeps the panic intact for [`wait`]
/// to re-raise on the calling thread, which is where an unbridged call would
/// have raised it.
///
/// `AssertUnwindSafe` is sound here because nothing observes the future's
/// state after the catch: the payload is forwarded and immediately resumed, so
/// no partially-updated value is ever read across the unwind boundary. The
/// state these futures touch is `Arc`-backed and shared with the caller, whose
/// own unwind is what the resumed panic drives.
fn dispatch<F, T>(handle: &Handle, future: F) -> mpsc::Receiver<Result<T, PanicPayload>>
where
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let (tx, rx) = mpsc::sync_channel(1);
    handle.spawn(async move {
        let outcome = AssertUnwindSafe(future).catch_unwind().await;
        // A send failure means the receiver is gone, which cannot happen while
        // `block_on_async` is blocked on it; ignoring it keeps the task from
        // panicking during runtime shutdown.
        let _ = tx.send(outcome);
    });
    rx
}

fn wait<T>(rx: mpsc::Receiver<Result<T, PanicPayload>>) -> T {
    match rx.recv() {
        Ok(Ok(value)) => value,
        // Re-raise the original panic on this thread, payload and all, so the
        // failure reads the same as it would from a direct `.await`.
        Ok(Err(payload)) => std::panic::resume_unwind(payload),
        // The task neither produced a value nor panicked, so it was dropped
        // before completing: the runtime it was spawned on shut down mid-call.
        Err(_) => panic!("block_on_async task was dropped before producing a value"),
    }
}

/// Run an async future to completion from a synchronous context.
///
/// The future runs as a task on a multi-threaded runtime and the calling
/// thread blocks until it finishes. On a runtime worker the wait happens
/// inside [`tokio::task::block_in_place`] so the scheduler hands this thread's
/// core to another worker instead of losing it for the duration.
///
/// The future must be `'static` because it is spawned; callers that need to
/// borrow should clone the (cheap, `Arc`-backed) state they need into an
/// `async move` block.
///
/// # Panics
///
/// A panic inside `future` is caught in the spawned task and re-raised here
/// with its original payload, so it reads exactly as it would have from a
/// direct `.await` on the calling thread.
///
/// Panics separately if the spawned task is dropped without producing a value
/// or a panic, which means the runtime it was spawned on shut down mid-call.
pub fn block_on_async<F, T>(future: F) -> T
where
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    match Handle::try_current() {
        // A current-thread runtime has exactly one thread — this one — so a
        // task spawned on it could never run while we block. Hand the future
        // to the fallback runtime instead.
        Ok(handle) if handle.runtime_flavor() == RuntimeFlavor::CurrentThread => {
            wait(dispatch(fallback_runtime().handle(), future))
        }
        Ok(handle) => {
            let rx = dispatch(&handle, future);
            // Release this thread's scheduler core for the duration of the
            // wait. Off a worker thread (the main thread inside
            // `Runtime::block_on`, or a `spawn_blocking` thread) this is a
            // no-op pass-through, which is exactly what we want.
            tokio::task::block_in_place(move || wait(rx))
        }
        Err(_) => wait(dispatch(fallback_runtime().handle(), future)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

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

    #[tokio::test(flavor = "current_thread")]
    async fn works_inside_current_thread_runtime() {
        let result = block_on_async(async { 42 });
        assert_eq!(result, 42);
    }

    // This test creates a current-thread runtime (no existing runtime) then calls
    // block_on_async inside it. The inner call detects the current-thread runtime
    // and dispatches to the fallback runtime to avoid deadlock.
    #[test]
    fn handles_nested_calls_outside_runtime() {
        let result = block_on_async(async { block_on_async(async { 42 }) });
        assert_eq!(result, 42);
    }

    /// A panicking bridged future must fail the caller with its own panic,
    /// not with a generic "the task was dropped" report. The payload is what
    /// carries the message and the `#[track_caller]` location, so losing it
    /// turns every panic behind the bridge into the same unactionable line.
    #[test]
    fn a_panicking_future_re_raises_the_original_payload() {
        // The default hook would print the caught panic and make a passing
        // test look like a failing one.
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let caught = std::panic::catch_unwind(AssertUnwindSafe(|| {
            block_on_async(async { panic!("bridged work exploded") })
        }));
        std::panic::set_hook(previous);

        let payload = caught.expect_err("the caller must see the panic");
        // A literal `panic!("msg")` yields a `&'static str` payload; a
        // formatted one yields a `String`.
        let message = payload
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| payload.downcast_ref::<String>().map(String::as_str));
        assert_eq!(
            message,
            Some("bridged work exploded"),
            "the original panic payload must reach the caller"
        );
    }

    /// The property that makes the bridge safe, asserted directly: the future
    /// never runs on the thread that called in.
    ///
    /// This is the deterministic half of the reactor-hang regression. Driving
    /// the future on the calling thread means driving it with that thread's
    /// tokio park token, which is the same token the caller's own task is
    /// parked on — and a single token cannot hold two pending wakeups. Any
    /// reimplementation that reaches for `Handle::block_on`,
    /// `Runtime::block_on`, or a hand-rolled poll loop on this thread fails
    /// here rather than in an intermittent reactor hang.
    #[test]
    fn future_never_runs_on_the_calling_thread() {
        fn assert_off_thread() {
            let caller = std::thread::current().id();
            let ran_on = block_on_async(async move { std::thread::current().id() });
            assert_ne!(
                caller, ran_on,
                "the bridged future must not be driven on the calling thread"
            );
        }

        // Outside any runtime.
        assert_off_thread();

        for threads in [1usize, 4] {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(threads)
                .enable_all()
                .build()
                .expect("build multi-thread runtime");
            rt.block_on(async { assert_off_thread() });
            // ... and from a worker rather than the `block_on` thread.
            rt.block_on(async {
                tokio::spawn(async { assert_off_thread() })
                    .await
                    .expect("spawned task")
            });
        }

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build current-thread runtime");
        rt.block_on(async { assert_off_thread() });
    }

    /// Regression for the reactor `rv sync` hang.
    ///
    /// Reproduces `Resolver::resolve_workspace`'s shape: one task, driven by
    /// `Runtime::block_on` on this thread, fanning modules out through
    /// `buffer_unordered`, each module fanning its dependencies out through a
    /// second, nested `buffer_unordered`, and each dependency crossing the
    /// sync bridge after work that completes on another thread.
    ///
    /// Both `FuturesUnordered` layers rely on the caller task's single
    /// park/unpark token to be re-polled. The old
    /// `block_in_place(|| handle.block_on(..))` bridge drove its future with
    /// that same token, so a wakeup raised for the *outer* task while this
    /// thread sat inside the nested `block_on` was consumed by the nested
    /// park. The inner layer then held ready work that nothing would ever come
    /// back for, and the process went idle forever.
    ///
    /// The assertion is therefore just that the work finishes at all; the
    /// timeout is what a regression trips.
    #[test]
    fn nested_bridge_calls_do_not_steal_the_caller_task_wakeup() {
        use futures::stream::{self, StreamExt};

        // Drive the runtime on a thread of our own so a regression fails the
        // test instead of hanging CI until the job is killed.
        let (done_tx, done_rx) = mpsc::channel();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(4)
                .enable_all()
                .build()
                .expect("build runtime");
            let count = rt.block_on(async {
                stream::iter(0..64u32)
                    .map(|_module| async move {
                        stream::iter(0..16u32)
                            .map(|dep| async move {
                                // Completes off-thread, so it wakes the one
                                // caller task at an unpredictable moment.
                                tokio::task::spawn_blocking(move || {
                                    std::thread::sleep(Duration::from_micros(
                                        20 + u64::from(dep % 7) * 10,
                                    ));
                                })
                                .await
                                .expect("blocking task");
                                // ... and now cross the bridge from inside it.
                                // The bridged future parks too, which is what
                                // opens the window for a sibling's wakeup to
                                // land while this thread is inside the bridge.
                                block_on_async(async move {
                                    tokio::task::spawn_blocking(move || {
                                        std::thread::sleep(Duration::from_micros(
                                            20 + u64::from(dep % 5) * 10,
                                        ));
                                    })
                                    .await
                                    .expect("bridged blocking task");
                                    tokio::task::yield_now().await;
                                    dep
                                })
                            })
                            .buffer_unordered(4)
                            .count()
                            .await
                    })
                    // Same fan-out as MAX_WORKSPACE_MODULE_CONCURRENCY.
                    .buffer_unordered(4)
                    .count()
                    .await
            });
            let _ = done_tx.send(count);
        });

        let count = done_rx
            .recv_timeout(Duration::from_secs(120))
            .expect("sync bridge deadlocked: the caller task's wakeup was stolen");
        assert_eq!(count, 64);
    }
}
