//! Integration tests for [`rv_config::LockfileGuard`].
//!
//! Regression coverage for the concurrent `rv sync` last-writer-wins bug:
//! two `rv sync` runs invoked in parallel must serialize their
//! read-resolve-write of `rv.lock`. The guard's exclusive `fs2` advisory
//! lock is what provides that mutual exclusion, so we verify here that a
//! second `acquire` on the same project root blocks until the first guard
//! is dropped. The lock file lives under a cache root (shared across the
//! contending callers) rather than the project working tree.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use rv_config::LockfileGuard;

/// Two concurrent `acquire` calls on the same project root must not
/// both hold the lock at the same time: the second call must block until
/// the first guard is dropped.
#[test]
fn second_acquire_blocks_until_first_is_dropped() {
    let cache = tempfile::tempdir().expect("cache tempdir");
    let cache_root = cache.path().to_path_buf();
    let dir = tempfile::tempdir().expect("tempdir");
    let project_root = dir.path().to_path_buf();

    // Thread A grabs the guard first and holds it for `hold_for`.
    let hold_for = Duration::from_millis(300);
    let a_acquired = Arc::new(AtomicBool::new(false));
    let a_released = Arc::new(AtomicBool::new(false));

    let a_cache = cache_root.clone();
    let a_root = project_root.clone();
    let a_acquired_cl = Arc::clone(&a_acquired);
    let a_released_cl = Arc::clone(&a_released);
    let thread_a = thread::spawn(move || {
        let guard = LockfileGuard::acquire(&a_cache, &a_root, Duration::from_secs(5))
            .expect("thread A acquire");
        a_acquired_cl.store(true, Ordering::SeqCst);
        thread::sleep(hold_for);
        a_released_cl.store(true, Ordering::SeqCst);
        drop(guard);
    });

    // Wait until thread A holds the lock so thread B's acquire is guaranteed
    // to contend.
    let spin_start = Instant::now();
    while !a_acquired.load(Ordering::SeqCst) {
        assert!(
            spin_start.elapsed() < Duration::from_secs(5),
            "thread A never acquired the guard"
        );
        thread::sleep(Duration::from_millis(5));
    }

    // Thread B attempts to acquire the same guard. It must block until A
    // releases.
    let b_cache = cache_root.clone();
    let b_root = project_root.clone();
    let a_released_for_b = Arc::clone(&a_released);
    let thread_b = thread::spawn(move || {
        let before = Instant::now();
        let guard = LockfileGuard::acquire(&b_cache, &b_root, Duration::from_secs(5))
            .expect("thread B acquire");
        let waited = before.elapsed();
        // When B finally acquires the lock, A must already have released
        // it. This is the load-bearing invariant: mutual exclusion held.
        assert!(
            a_released_for_b.load(Ordering::SeqCst),
            "thread B acquired the guard while thread A still held it"
        );
        drop(guard);
        waited
    });

    thread_a.join().expect("thread A join");
    let waited = thread_b.join().expect("thread B join");

    // Sanity: B should have waited approximately as long as A held the
    // lock. Allow generous slack for slow CI hosts.
    assert!(
        waited >= Duration::from_millis(100),
        "thread B did not visibly block; waited only {:?} (expected >= 100ms)",
        waited
    );
}

/// After a guard is dropped, a fresh acquire on the same path must succeed
/// immediately. This guards against accidentally leaking the underlying
/// file lock past the guard's lifetime.
#[test]
fn dropping_guard_releases_lock_for_next_acquire() {
    let cache = tempfile::tempdir().expect("cache tempdir");
    let cache_root = cache.path().to_path_buf();
    let dir = tempfile::tempdir().expect("tempdir");
    let project_root = dir.path().to_path_buf();

    {
        let g = LockfileGuard::acquire(&cache_root, &project_root, Duration::from_secs(5))
            .expect("first acquire");
        drop(g);
    }

    // Should not block.
    let started = Instant::now();
    let g2 = LockfileGuard::acquire(&cache_root, &project_root, Duration::from_secs(5))
        .expect("second acquire");
    assert!(
        started.elapsed() < Duration::from_millis(200),
        "second acquire was unexpectedly slow after drop"
    );
    drop(g2);
}

/// Regression: a second `acquire` whose `timeout` elapses before
/// the holder releases must surface a `TimedOut` error rather than blocking
/// forever. Prior to this fix, `LockfileGuard::acquire` called the blocking
/// `lock_exclusive` directly, so a stale guard from a crashed process would
/// wedge every subsequent `rv sync` invocation.
#[test]
fn acquire_times_out_when_holder_outlasts_deadline() {
    let cache = tempfile::tempdir().expect("cache tempdir");
    let cache_root = cache.path().to_path_buf();
    let dir = tempfile::tempdir().expect("tempdir");
    let project_root = dir.path().to_path_buf();

    // Thread A holds the guard for ~200 ms.
    let a_cache = cache_root.clone();
    let a_root = project_root.clone();
    let a_acquired = Arc::new(AtomicBool::new(false));
    let a_acquired_cl = Arc::clone(&a_acquired);
    let thread_a = thread::spawn(move || {
        let guard =
            LockfileGuard::acquire(&a_cache, &a_root, Duration::from_secs(5)).expect("A acquire");
        a_acquired_cl.store(true, Ordering::SeqCst);
        thread::sleep(Duration::from_millis(200));
        drop(guard);
    });

    // Spin until A has the lock so B is guaranteed to contend.
    let spin_start = Instant::now();
    while !a_acquired.load(Ordering::SeqCst) {
        assert!(
            spin_start.elapsed() < Duration::from_secs(5),
            "thread A never acquired the guard"
        );
        thread::sleep(Duration::from_millis(5));
    }

    // Thread B uses a 100 ms timeout — must fail.
    let started = Instant::now();
    let err = LockfileGuard::acquire(&cache_root, &project_root, Duration::from_millis(100))
        .expect_err("expected TimedOut while A still holds the guard");
    let elapsed = started.elapsed();
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::TimedOut,
        "expected TimedOut, got {:?}: {err}",
        err.kind()
    );
    // The error must arrive promptly: the polling loop should not let the
    // failure leak much past the configured timeout.
    assert!(
        elapsed < Duration::from_millis(500),
        "TimedOut surfaced too late: {elapsed:?}"
    );

    thread_a.join().expect("A join");

    // After A releases, a normal acquire must succeed again.
    let _g = LockfileGuard::acquire(&cache_root, &project_root, Duration::from_secs(5))
        .expect("acquire after holder releases");
}
