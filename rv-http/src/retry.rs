//! The one retry rule Raeva's HTTP clients follow.
//!
//! An attempt that fails on the way, by a timeout or a broken connection,
//! is retried after an exponential, jittered backoff that starts at 500 ms
//! and doubles up to 30 s. A server that answers it is busy (429, 502, 503
//! or 504) is asked again after 5 s times the retry's number, as
//! maven-resolver waits, plus up to half that again of jitter; its
//! `Retry-After` is a minimum. A `Retry-After` past [`MAX_BUSY_WAIT`] ends
//! the retries at once: asking again sooner than the server said only
//! spends the caller's time and the server's rate limit. A busy answer also
//! holds back the other requests to that server, within their budgets and
//! through their shared [`Cooldown`], until the wait ends. A host name that
//! did not resolve is looked up once more, after the same backoff as a
//! timeout, but not after two failed lookups in a row: then the other
//! requests to that server get no second lookup either, until one gets past
//! the lookup. Retrying stops after
//! [`RetryPolicy::retries`] retries, or as soon as the next wait would take
//! the total time spent waiting past [`RetryPolicy::budget`]; the last error
//! is returned then without waiting.

use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use backon::{BackoffBuilder, ExponentialBuilder};
use reqwest::Url;
use tokio::time::Instant;

/// The longest wait after a busy answer. A `Retry-After` past it is not
/// waited for.
pub const MAX_BUSY_WAIT: Duration = Duration::from_secs(60);

/// How many times, and for how long in total, a request may be retried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct RetryPolicy {
    /// Retries after the first attempt.
    pub retries: usize,
    /// The most time all waits between attempts may add up to.
    pub budget: Duration,
}

impl RetryPolicy {
    /// `retries` retries, with a budget of one `timeout` per attempt plus
    /// five seconds. The arithmetic saturates, so huge values from library
    /// callers cannot overflow.
    pub fn new(retries: usize, timeout: Duration) -> Self {
        let attempts = u32::try_from(retries).unwrap_or(u32::MAX).saturating_add(1);
        Self {
            retries,
            budget: timeout
                .saturating_mul(attempts)
                .saturating_add(Duration::from_secs(5)),
        }
    }
}

/// How one attempt failed.
#[derive(Debug)]
pub enum Outcome<E> {
    /// Retrying cannot help.
    Permanent(E),
    /// The request failed on the way; a later attempt may succeed.
    Transient(E),
    /// The host name did not resolve. It is looked up once more, for a
    /// resolver that failed for a moment, unless the last lookup failed too.
    Unresolved(E),
    /// The server answered that it cannot serve the request now.
    Busy {
        /// The error the attempt failed with.
        error: E,
        /// The server's `Retry-After`, which the next wait is at least.
        retry_after: Option<Duration>,
    },
}

impl<E> Outcome<E> {
    /// An [`Outcome::Permanent`] holding `error`.
    pub fn permanent(error: E) -> Self {
        Outcome::Permanent(error)
    }

    /// An [`Outcome::Transient`] holding `error`.
    pub fn transient(error: E) -> Self {
        Outcome::Transient(error)
    }

    /// Whether a later attempt may succeed.
    pub fn is_transient(&self) -> bool {
        !matches!(self, Outcome::Permanent(_))
    }

    /// The error, whichever kind of failure it was.
    pub fn into_error(self) -> E {
        match self {
            Outcome::Permanent(error)
            | Outcome::Transient(error)
            | Outcome::Unresolved(error)
            | Outcome::Busy { error, .. } => error,
        }
    }
}

/// When the requests to one server may next go out. A busy answer to one
/// of them holds back the others for the wait it set off, so they do not
/// each spend a retry on the same window. Once two lookups of the host
/// name failed in a row, a failed lookup gets no retry until an attempt
/// gets past the lookup, so a repository whose host is gone costs one wait
/// per run, not one per file.
#[derive(Debug, Default)]
pub struct Cooldown {
    until: Mutex<Option<Instant>>,
    unresolvable: AtomicBool,
}

impl Cooldown {
    fn hold(&self, wait: Duration) {
        let until = Instant::now() + wait;
        let mut held = self.until.lock().unwrap_or_else(PoisonError::into_inner);
        if held.is_none_or(|held| held < until) {
            *held = Some(until);
        }
    }

    fn remaining(&self) -> Duration {
        self.until
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .map_or(Duration::ZERO, |until| {
                until.saturating_duration_since(Instant::now())
            })
    }
}

/// A [`Cooldown`] per server origin.
#[derive(Debug, Default)]
pub struct Cooldowns(Mutex<HashMap<String, Arc<Cooldown>>>);

impl Cooldowns {
    /// The cooldown of the origin `url` names.
    pub fn of(&self, url: &Url) -> Arc<Cooldown> {
        let mut origins = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        Arc::clone(
            origins
                .entry(url.origin().ascii_serialization())
                .or_default(),
        )
    }
}

/// Run `attempt` until it succeeds, fails permanently, or the policy stops
/// retrying (see the module documentation), each attempt after `cooldown`
/// lets it or the budget runs out; that wait counts against the budget too.
/// `on_retry` sees each failure that will be retried and the wait
/// before the next attempt.
pub async fn run<T, E, F, Fut>(
    policy: &RetryPolicy,
    cooldown: &Cooldown,
    mut attempt: F,
    mut on_retry: impl FnMut(&E, Duration),
) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, Outcome<E>>>,
{
    let mut backoff = ExponentialBuilder::default()
        .with_min_delay(Duration::from_millis(500))
        .with_max_delay(Duration::from_secs(30))
        .with_factor(2.0)
        .with_jitter()
        .without_max_times()
        .build();
    let mut retries = 0;
    let mut waited = Duration::ZERO;
    let mut unresolved = false;
    loop {
        loop {
            let held = cooldown
                .remaining()
                .min(policy.budget.saturating_sub(waited));
            if held.is_zero() {
                break;
            }
            tokio::time::sleep(held).await;
            waited += held;
        }
        let outcome = attempt().await;
        // Any other outcome got past the lookup, or needed none.
        let lookup_failed = matches!(outcome, Err(Outcome::Unresolved(_)));
        let failed_before = std::mem::replace(&mut unresolved, lookup_failed);
        if !lookup_failed && cooldown.unresolvable.load(Ordering::Relaxed) {
            cooldown.unresolvable.store(false, Ordering::Relaxed);
        }
        let (error, busy) = match outcome {
            Ok(value) => return Ok(value),
            Err(Outcome::Permanent(error)) => return Err(error),
            Err(Outcome::Transient(error)) => (error, None),
            Err(Outcome::Unresolved(error)) => {
                if failed_before {
                    cooldown.unresolvable.store(true, Ordering::Relaxed);
                }
                if failed_before || cooldown.unresolvable.load(Ordering::Relaxed) {
                    return Err(error);
                }
                (error, None)
            }
            Err(Outcome::Busy { error, retry_after }) => (error, Some(retry_after)),
        };
        if retries >= policy.retries {
            return Err(error);
        }
        let wait = match busy {
            None => backoff.next().unwrap_or(Duration::from_secs(30)),
            Some(Some(retry_after)) if retry_after > MAX_BUSY_WAIT => return Err(error),
            Some(retry_after) => {
                let number = u32::try_from(retries).unwrap_or(u32::MAX).saturating_add(1);
                let step = Duration::from_secs(5).saturating_mul(number);
                let jittered = step.saturating_add(step.mul_f64(fastrand::f64() / 2.0));
                jittered
                    .max(retry_after.unwrap_or_default())
                    .min(MAX_BUSY_WAIT)
            }
        };
        match waited.checked_add(wait) {
            Some(total) if total <= policy.budget => waited = total,
            _ => return Err(error),
        }
        if busy.is_some() {
            cooldown.hold(wait);
        }
        on_retry(&error, wait);
        tokio::time::sleep(wait).await;
        retries += 1;
    }
}

#[cfg(test)]
mod tests {
    use std::ops::RangeInclusive;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    fn after(secs: u64) -> Option<Outcome<&'static str>> {
        Some(Outcome::Busy {
            error: "busy",
            retry_after: Some(Duration::from_secs(secs)),
        })
    }

    #[tokio::test(start_paused = true)]
    async fn retries_transient_failures_within_the_count_and_budget() {
        type Failure = fn(usize) -> Option<Outcome<&'static str>>;
        type Case = (
            usize,
            u64,
            Failure,
            RangeInclusive<usize>,
            RangeInclusive<u64>,
        );
        // Retries, budget in seconds, the failure of attempt n (none for
        // success), the attempts made and the milliseconds waited.
        let cases: [Case; 15] = [
            (
                3,
                600,
                |_| Some(Outcome::transient("busy")),
                4..=4,
                0..=600_000,
            ),
            (3, 600, |_| Some(Outcome::permanent("busy")), 1..=1, 0..=0),
            (
                3,
                600,
                |n| (n < 2).then(|| Outcome::transient("busy")),
                3..=3,
                0..=600_000,
            ),
            (
                3,
                600,
                |_| {
                    Some(Outcome::Busy {
                        error: "busy",
                        retry_after: None,
                    })
                },
                4..=4,
                30_000..=45_000,
            ),
            (1, 600, |_| after(7), 2..=2, 7000..=7500),
            (1, 600, |_| after(0), 2..=2, 5000..=7500),
            (1, 600, |_| after(60), 2..=2, 60_000..=60_000),
            (3, 600, |_| after(61), 1..=1, 0..=0),
            (5, 10, |_| after(30), 1..=1, 0..=0),
            (usize::MAX, 20, |_| after(1), 2..=3, 5000..=20_000),
            // A host name that did not resolve is tried once more.
            (
                3,
                600,
                |n| (n < 1).then_some(Outcome::Unresolved("dns")),
                2..=2,
                0..=1000,
            ),
            (
                3,
                600,
                |_| Some(Outcome::Unresolved("dns")),
                2..=2,
                0..=1000,
            ),
            (0, 600, |_| Some(Outcome::Unresolved("dns")), 1..=1, 0..=0),
            (
                3,
                600,
                |n| {
                    Some(if n == 0 {
                        Outcome::transient("busy")
                    } else {
                        Outcome::Unresolved("dns")
                    })
                },
                3..=3,
                0..=3000,
            ),
            (
                3,
                600,
                |n| match n {
                    0 | 2 => Some(Outcome::Unresolved("dns")),
                    1 => Some(Outcome::transient("busy")),
                    _ => None,
                },
                4..=4,
                0..=7000,
            ),
        ];
        for (retries, budget, failure, attempts, waited) in cases {
            let made = AtomicUsize::new(0);
            let start = tokio::time::Instant::now();
            let policy = RetryPolicy {
                retries,
                budget: Duration::from_secs(budget),
            };
            let result = run(
                &policy,
                &Cooldown::default(),
                || {
                    let failure = failure(made.fetch_add(1, Ordering::SeqCst));
                    async move { failure.map_or(Ok(()), Err) }
                },
                |_, _| {},
            )
            .await;
            let made = made.load(Ordering::SeqCst);
            assert!(attempts.contains(&made), "{made} attempts");
            // Each sleep ends on the next millisecond tick, so the waits a
            // budget admits can add up to one more millisecond per retry.
            let elapsed = u64::try_from(start.elapsed().as_millis()).unwrap();
            let rounding = u64::try_from(made - 1).unwrap();
            assert!(
                *waited.start() <= elapsed && elapsed <= waited.end() + rounding,
                "{elapsed} ms"
            );
            assert_eq!(result.is_ok(), failure(made - 1).is_none(), "{result:?}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_busy_answer_holds_back_the_other_requests_to_its_server() {
        let policy = RetryPolicy {
            retries: 1,
            budget: Duration::from_secs(600),
        };
        let cooldown = Cooldown::default();
        let start = tokio::time::Instant::now();
        let made = AtomicUsize::new(0);
        let first = run(
            &policy,
            &cooldown,
            || {
                let busy = made.fetch_add(1, Ordering::SeqCst) == 0;
                async move {
                    if busy {
                        return Err(Outcome::Busy {
                            error: "busy",
                            retry_after: None,
                        });
                    }
                    Ok(start.elapsed())
                }
            },
            |_, _| {},
        );
        let second = async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            run(
                &policy,
                &cooldown,
                || async { Ok::<_, Outcome<&str>>(start.elapsed()) },
                |_, _| {},
            )
            .await
        };
        let (first, second) = tokio::join!(first, second);
        let window = Duration::from_secs(5)..=Duration::from_millis(7500);
        for sent in [first.unwrap(), second.unwrap()] {
            assert!(window.contains(&sent), "{sent:?}");
        }

        // A hold that grows while a request waits holds it back to the end.
        let cooldown = Cooldown::default();
        cooldown.hold(Duration::from_secs(10));
        let extend = async {
            tokio::time::sleep(Duration::from_secs(5)).await;
            cooldown.hold(Duration::from_secs(20));
        };
        let start = tokio::time::Instant::now();
        let ((), sent) = tokio::join!(
            extend,
            run(
                &policy,
                &cooldown,
                || async { Ok::<_, Outcome<&str>>(start.elapsed()) },
                |_, _| {},
            )
        );
        assert_eq!(sent, Ok(Duration::from_secs(25)));
    }

    /// A cooldown that outlasts the budget holds a request back only until
    /// the budget runs out, and leaves it no time to wait for a retry.
    #[tokio::test(start_paused = true)]
    async fn a_cooldown_wait_counts_against_the_budget() {
        let policy = RetryPolicy {
            retries: 3,
            budget: Duration::from_secs(10),
        };
        let cooldown = Cooldown::default();
        cooldown.hold(Duration::from_secs(1000));
        let start = tokio::time::Instant::now();
        let made = AtomicUsize::new(0);
        let result = run(
            &policy,
            &cooldown,
            || {
                made.fetch_add(1, Ordering::SeqCst);
                async {
                    Err::<(), _>(Outcome::Busy {
                        error: "busy",
                        retry_after: None,
                    })
                }
            },
            |_, _| {},
        )
        .await;
        assert_eq!(result, Err("busy"));
        assert_eq!(made.load(Ordering::SeqCst), 1);
        assert_eq!(start.elapsed(), Duration::from_secs(10));
    }

    /// Two failed lookups in a row end a request, and the next request to
    /// that server gets no second lookup, until an attempt gets past the
    /// lookup.
    #[tokio::test(start_paused = true)]
    async fn a_name_that_failed_twice_gets_no_more_lookups() {
        type Plan = fn(usize) -> Result<(), Outcome<&'static str>>;
        let policy = RetryPolicy {
            retries: 3,
            budget: Duration::from_secs(600),
        };
        let cooldown = Cooldown::default();
        let attempts = |plan: Plan| {
            let made = AtomicUsize::new(0);
            let cooldown = &cooldown;
            async move {
                let _ = run(
                    &policy,
                    cooldown,
                    || {
                        let result = plan(made.fetch_add(1, Ordering::SeqCst));
                        async move { result }
                    },
                    |_, _| {},
                )
                .await;
                made.load(Ordering::SeqCst)
            }
        };
        let dns: Plan = |_| Err(Outcome::Unresolved("dns"));
        assert_eq!(attempts(dns).await, 2);
        assert_eq!(attempts(dns).await, 1);
        assert_eq!(attempts(|_| Err(Outcome::permanent("404"))).await, 1);
        assert_eq!(attempts(dns).await, 2);
        assert_eq!(attempts(|_| Ok(())).await, 1);
        // A lookup that worked in between starts the count again.
        let plan: Plan = |n| match n {
            0 | 2 => Err(Outcome::Unresolved("dns")),
            1 => Err(Outcome::transient("503")),
            _ => Ok(()),
        };
        assert_eq!(attempts(plan).await, 4);
    }

    #[test]
    fn the_budget_saturates() {
        let secs = Duration::from_secs;
        assert_eq!(
            RetryPolicy::new(usize::MAX, Duration::MAX).budget,
            Duration::MAX
        );
        assert_eq!(RetryPolicy::new(2, secs(30)).budget, secs(95));
    }
}
