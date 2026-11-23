//! The one retry rule Raeva's HTTP clients follow.
//!
//! An attempt that fails on the way, by a timeout or a broken connection,
//! is retried after an exponential, jittered backoff that starts at 500 ms
//! and doubles up to 30 s. A server that answers it is busy (429, 502, 503
//! or 504) is asked again after 5 s times the retry's number, as
//! maven-resolver waits, plus up to half that again of jitter; its
//! `Retry-After` is a minimum. A `Retry-After` past [`MAX_BUSY_WAIT`] ends
//! the retries at once: asking again sooner than the server said only
//! spends the caller's time and the server's rate limit. Until that time is
//! up, the other requests to that server fail at once, unsent, with the
//! same answer. A shorter busy answer holds back the other requests to that
//! server, through their shared [`Cooldown`], until the wait ends. A host
//! name that
//! did not resolve is looked up once more, after the same backoff as a
//! timeout, but not after two failed lookups in a row: then the other
//! requests to that server get no second lookup either, until one gets past
//! the lookup. Retrying stops after
//! [`RetryPolicy::retries`] retries, or as soon as the next wait after a
//! failure on the way would take the total of those waits past
//! [`RetryPolicy::budget`]; the last error is returned then without
//! waiting. The waits a busy server asks for count against no budget, as in
//! maven-resolver.

use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use backon::{BackoffBuilder, ExponentialBuilder};
use reqwest::{StatusCode, Url};
use tokio::time::Instant;

/// The longest wait after a busy answer, maven-resolver's default
/// `retryHandler.intervalMax`. A `Retry-After` past it is not waited for.
pub const MAX_BUSY_WAIT: Duration = Duration::from_secs(300);

/// How many times, and for how long in total, a request may be retried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct RetryPolicy {
    /// Retries after the first attempt.
    pub retries: usize,
    /// The most time the waits after failures on the way may add up to.
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
        /// The status the server answered with.
        status: StatusCode,
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
    /// A busy answer that asked for more than [`MAX_BUSY_WAIT`]: until
    /// when, its status and its `Retry-After`.
    refused: Mutex<Option<(Instant, StatusCode, Duration)>>,
    /// For the cooldown of optional requests, that of the other requests
    /// to the server: optional requests wait out its holds and refusals
    /// too.
    under: Option<Arc<Cooldown>>,
}

impl Cooldown {
    fn refuse(&self, status: StatusCode, retry_after: Duration) {
        self.refuse_from(status, retry_after, Instant::now());
    }

    /// Refuse the requests to the server for the `retry_after` a busy
    /// answer with `status` asked for when it came `answered`, as [`run`]
    /// does when the answer is past [`MAX_BUSY_WAIT`]: for an answer to an
    /// optional request that a caller came to need.
    pub fn refuse_from(&self, status: StatusCode, retry_after: Duration, answered: Instant) {
        // A server's `Retry-After` can be any number of seconds, past what an
        // `Instant` holds; a century outlasts any run.
        let until = answered + retry_after.min(Duration::from_secs(100 * 365 * 24 * 60 * 60));
        let mut refused = self.refused.lock().unwrap_or_else(PoisonError::into_inner);
        if refused.is_none_or(|(held, ..)| held < until) {
            *refused = Some((until, status, retry_after));
        }
    }

    /// The status and `Retry-After` of a refusal not yet over.
    pub fn refusal(&self) -> Option<(StatusCode, Duration)> {
        let refused = *self.refused.lock().unwrap_or_else(PoisonError::into_inner);
        refused
            .filter(|(until, ..)| *until > Instant::now())
            .map(|(_, status, retry_after)| (status, retry_after))
            .or_else(|| self.under.as_ref()?.refusal())
    }

    /// Whether a failed lookup gets no retry. Optional requests go by the
    /// other requests' lookups only, so that theirs change nothing a needed
    /// request meets.
    fn unresolvable(&self) -> bool {
        match &self.under {
            Some(under) => under.unresolvable(),
            None => self.unresolvable.load(Ordering::Relaxed),
        }
    }

    fn hold(&self, wait: Duration) {
        let until = Instant::now() + wait;
        let mut held = self.until.lock().unwrap_or_else(PoisonError::into_inner);
        if held.is_none_or(|held| held < until) {
            *held = Some(until);
        }
    }

    fn remaining(&self) -> Duration {
        let own = (self.until.lock().unwrap_or_else(PoisonError::into_inner))
            .map_or(Duration::ZERO, |until| {
                until.saturating_duration_since(Instant::now())
            });
        own.max((self.under.as_ref()).map_or(Duration::ZERO, |under| under.remaining()))
    }

    /// Whether a request to the server may go out now, without a wait.
    pub fn is_clear(&self) -> bool {
        self.refusal().is_none() && self.remaining().is_zero()
    }

    /// Wait out what holds back the requests to the server, unless it is
    /// refused: then the status and `Retry-After` of that refusal.
    /// Requests sent together are let through at once this way, then each
    /// is run with [`run_admitted`], with no await in between.
    ///
    /// # Errors
    ///
    /// The refusal in force, before or after a wait.
    pub async fn ready(&self) -> Result<(), (StatusCode, Duration)> {
        loop {
            if let Some(refusal) = self.refusal() {
                return Err(refusal);
            }
            let held = self.remaining();
            if held.is_zero() {
                return Ok(());
            }
            tokio::time::sleep(held).await;
        }
    }
}

/// A [`Cooldown`] per server origin, and one per origin for optional
/// requests.
#[derive(Debug, Default)]
pub struct Cooldowns {
    origins: Mutex<HashMap<String, Arc<Cooldown>>>,
    optional: Mutex<HashMap<String, Arc<Cooldown>>>,
}

impl Cooldowns {
    /// The cooldown of the origin `url` names.
    pub fn of(&self, url: &Url) -> Arc<Cooldown> {
        let mut origins = self.origins.lock().unwrap_or_else(PoisonError::into_inner);
        Arc::clone(
            origins
                .entry(url.origin().ascii_serialization())
                .or_default(),
        )
    }

    /// The cooldown of requests to the origin `url` names whose answers no
    /// caller may need, such as a sidecar asked for in case another is
    /// missing: they wait out what holds back the other requests there,
    /// but what they meet holds back only each other.
    pub fn of_optional(&self, url: &Url) -> Arc<Cooldown> {
        let mut optional = self.optional.lock().unwrap_or_else(PoisonError::into_inner);
        let entry = optional.entry(url.origin().ascii_serialization());
        Arc::clone(entry.or_insert_with(|| {
            Arc::new(Cooldown {
                under: Some(self.of(url)),
                ..Cooldown::default()
            })
        }))
    }
}

/// Run `attempt` until it succeeds, fails permanently, or the policy stops
/// retrying (see the module documentation), each attempt after `cooldown`
/// lets it.
/// `on_retry` sees each failure that will be retried and the wait
/// before the next attempt. Until a `Retry-After` past [`MAX_BUSY_WAIT`]
/// that `cooldown` saw is up, nothing is sent, and the error is what
/// `refused` makes of that answer's status and `Retry-After`.
pub async fn run<T, E, F, Fut>(
    policy: &RetryPolicy,
    cooldown: &Cooldown,
    attempt: F,
    on_retry: impl FnMut(&E, Duration),
    refused: impl Fn(StatusCode, Duration) -> E,
) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, Outcome<E>>>,
{
    run_admitted(false, policy, cooldown, attempt, on_retry, refused).await
}

/// [`run`], but when `admitted`, for a request that [`Cooldown::ready`]
/// let through with others sent together, with no await since: its first
/// attempt goes out without another look at `cooldown`, so an answer to
/// one of the others does not keep it unsent, whichever goes out first.
/// Its retries wait as any do.
pub async fn run_admitted<T, E, F, Fut>(
    admitted: bool,
    policy: &RetryPolicy,
    cooldown: &Cooldown,
    mut attempt: F,
    mut on_retry: impl FnMut(&E, Duration),
    refused: impl Fn(StatusCode, Duration) -> E,
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
        if !(admitted && retries == 0)
            && let Err((status, retry_after)) = cooldown.ready().await
        {
            return Err(refused(status, retry_after));
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
                if failed_before || cooldown.unresolvable() {
                    return Err(error);
                }
                (error, None)
            }
            Err(Outcome::Busy {
                error,
                status,
                retry_after: Some(retry_after),
            }) if retry_after > MAX_BUSY_WAIT => {
                cooldown.refuse(status, retry_after);
                return Err(error);
            }
            Err(Outcome::Busy {
                error, retry_after, ..
            }) => (error, Some(retry_after)),
        };
        if retries >= policy.retries {
            return Err(error);
        }
        let wait = match busy {
            None => backoff.next().unwrap_or(Duration::from_secs(30)),
            Some(retry_after) => {
                let number = u32::try_from(retries).unwrap_or(u32::MAX).saturating_add(1);
                let step = Duration::from_secs(5).saturating_mul(number);
                let jittered = step.saturating_add(step.mul_f64(fastrand::f64() / 2.0));
                jittered
                    .max(retry_after.unwrap_or_default())
                    .min(MAX_BUSY_WAIT)
            }
        };
        if busy.is_some() {
            cooldown.hold(wait);
        } else {
            match waited.checked_add(wait) {
                Some(total) if total <= policy.budget => waited = total,
                _ => return Err(error),
            }
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

    /// A request that waits out a hold is not sent once a refusal has begun
    /// meanwhile, whether it waits in [`run`] or in [`Cooldown::ready`]
    /// before a pair is let through.
    #[tokio::test(start_paused = true)]
    async fn a_refusal_that_begins_during_a_hold_stops_the_waiting_requests() {
        let policy = RetryPolicy::new(1, Duration::from_secs(10));
        let cooldown = Cooldown::default();
        cooldown.hold(Duration::from_secs(30));
        let made = AtomicUsize::new(0);
        let refuse = async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            cooldown.refuse(StatusCode::TOO_MANY_REQUESTS, Duration::from_secs(600));
        };
        let sent = run(
            &policy,
            &cooldown,
            || {
                made.fetch_add(1, Ordering::SeqCst);
                async { Ok::<_, Outcome<&str>>(()) }
            },
            |_, _| {},
            |_, _| "refused",
        );
        let (sent, ready, ()) = tokio::join!(sent, cooldown.ready(), refuse);
        assert_eq!(sent, Err("refused"));
        let refusal = (StatusCode::TOO_MANY_REQUESTS, Duration::from_secs(600));
        assert_eq!(ready, Err(refusal));
        assert_eq!(made.into_inner(), 0);
    }

    /// An admitted request's first attempt goes out whatever the cooldown
    /// says by then, and its retries wait for it as any do.
    #[tokio::test(start_paused = true)]
    async fn only_the_first_attempt_of_an_admitted_request_skips_the_cooldown() {
        let policy = RetryPolicy::new(1, Duration::from_secs(10));
        let cooldown = Cooldown::default();
        assert_eq!(cooldown.ready().await, Ok(()));
        cooldown.refuse(StatusCode::TOO_MANY_REQUESTS, Duration::from_secs(600));
        for admitted in [true, false] {
            let made = AtomicUsize::new(0);
            let sent = run_admitted(
                admitted,
                &policy,
                &cooldown,
                || {
                    made.fetch_add(1, Ordering::SeqCst);
                    async { Err::<(), _>(Outcome::Transient("lost")) }
                },
                |_, _| {},
                |_, _| "refused",
            )
            .await;
            assert_eq!(
                (sent, made.into_inner()),
                (Err("refused"), usize::from(admitted))
            );
        }
    }

    /// A refusal an optional request meets holds back only optional
    /// requests, one the other requests meet holds back both, and one a
    /// caller takes on from an optional answer lasts from that answer.
    #[tokio::test(start_paused = true)]
    async fn an_optional_requests_refusal_holds_back_only_optional_requests() {
        let policy = RetryPolicy::new(1, Duration::from_secs(10));
        let refuse = |cooldown: Arc<Cooldown>| async move {
            let refused: Result<(), _> = run(
                &policy,
                &cooldown,
                || async { Err(after(600).unwrap()) },
                |_, _| {},
                |_, _| "refused",
            )
            .await;
            assert_eq!(refused, Err("busy"));
        };
        let cooldowns = Cooldowns::default();
        let url = |server| Url::parse(&format!("https://repo{server}.example/")).unwrap();

        refuse(cooldowns.of_optional(&url(0))).await;
        assert!(cooldowns.of(&url(0)).is_clear());
        assert!(!cooldowns.of_optional(&url(0)).is_clear());

        refuse(cooldowns.of(&url(1))).await;
        assert!(!cooldowns.of_optional(&url(1)).is_clear());

        let answered = Instant::now();
        tokio::time::advance(Duration::from_secs(590)).await;
        let status = StatusCode::TOO_MANY_REQUESTS;
        cooldowns
            .of(&url(2))
            .refuse_from(status, Duration::from_secs(600), answered);
        assert!(!cooldowns.of(&url(2)).is_clear());
        tokio::time::advance(Duration::from_secs(11)).await;
        assert!(cooldowns.of(&url(2)).is_clear());
    }

    /// Failed lookups of optional requests leave the other requests their
    /// second lookup, and leave optional requests theirs too.
    #[tokio::test(start_paused = true)]
    async fn optional_requests_failed_lookups_take_no_lookup_away() {
        let policy = RetryPolicy::new(1, Duration::from_secs(10));
        let cooldowns = Cooldowns::default();
        let url = Url::parse("https://repo.example/").unwrap();
        let lookups = |cooldown: Arc<Cooldown>, failures: usize| async move {
            let made = AtomicUsize::new(0);
            let sent = run(
                &policy,
                &cooldown,
                || {
                    let fail = made.fetch_add(1, Ordering::SeqCst) < failures;
                    async move {
                        if fail {
                            Err(Outcome::Unresolved("lookup"))
                        } else {
                            Ok(())
                        }
                    }
                },
                |_, _| {},
                |_, _| "refused",
            )
            .await;
            (sent, made.into_inner())
        };
        assert_eq!(
            lookups(cooldowns.of_optional(&url), 2).await,
            (Err("lookup"), 2)
        );
        assert_eq!(lookups(cooldowns.of_optional(&url), 1).await, (Ok(()), 2));
        assert_eq!(lookups(cooldowns.of(&url), 1).await, (Ok(()), 2));
    }

    fn after(secs: u64) -> Option<Outcome<&'static str>> {
        Some(Outcome::Busy {
            error: "busy",
            status: StatusCode::TOO_MANY_REQUESTS,
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
        let cases: [Case; 14] = [
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
                        status: StatusCode::SERVICE_UNAVAILABLE,
                        retry_after: None,
                    })
                },
                4..=4,
                30_000..=45_000,
            ),
            (1, 600, |_| after(7), 2..=2, 7000..=7500),
            (1, 600, |_| after(0), 2..=2, 5000..=7500),
            (1, 600, |_| after(300), 2..=2, 300_000..=300_000),
            (3, 600, |_| after(301), 1..=1, 0..=0),
            // A busy server's wait counts against no budget.
            (1, 10, |_| after(120), 2..=2, 120_000..=120_000),
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
                |_, _| "refused",
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
                            status: StatusCode::SERVICE_UNAVAILABLE,
                            retry_after: None,
                        });
                    }
                    Ok(start.elapsed())
                }
            },
            |_, _| {},
            |_, _| "refused",
        );
        let second = async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            run(
                &policy,
                &cooldown,
                || async { Ok::<_, Outcome<&str>>(start.elapsed()) },
                |_, _| {},
                |_, _| "refused",
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
                |_, _| "refused",
            )
        );
        assert_eq!(sent, Ok(Duration::from_secs(25)));
    }

    /// A `Retry-After` past the longest wait ends its request, and the other
    /// requests to that server fail without being sent, with its status and
    /// `Retry-After`, until that time is up.
    #[tokio::test(start_paused = true)]
    async fn a_retry_after_past_the_longest_wait_refuses_the_other_requests() {
        let policy = RetryPolicy {
            retries: 3,
            budget: Duration::from_secs(600),
        };
        let cooldown = Cooldown::default();
        let made = AtomicUsize::new(0);
        let request = || {
            run(
                &policy,
                &cooldown,
                || {
                    made.fetch_add(1, Ordering::SeqCst);
                    async {
                        Err::<(), _>(Outcome::Busy {
                            error: (StatusCode::SERVICE_UNAVAILABLE, None),
                            status: StatusCode::SERVICE_UNAVAILABLE,
                            retry_after: Some(Duration::from_secs(600)),
                        })
                    }
                },
                |_, _| {},
                |status, wait| (status, Some(wait)),
            )
        };
        assert_eq!(
            request().await,
            Err((StatusCode::SERVICE_UNAVAILABLE, None))
        );
        assert_eq!(made.load(Ordering::SeqCst), 1);
        tokio::time::sleep(Duration::from_secs(599)).await;
        assert_eq!(
            request().await,
            Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Some(Duration::from_secs(600))
            ))
        );
        assert_eq!(made.load(Ordering::SeqCst), 1);
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(
            request().await,
            Err((StatusCode::SERVICE_UNAVAILABLE, None))
        );
        assert_eq!(made.load(Ordering::SeqCst), 2);
    }

    /// A refusal fails a request at once, without waiting out a shorter
    /// hold first, and a `Retry-After` of any size holds.
    #[tokio::test(start_paused = true)]
    async fn a_refusal_does_not_wait_out_a_shorter_hold() {
        let policy = RetryPolicy {
            retries: 3,
            budget: Duration::from_secs(600),
        };
        let cooldown = Cooldown::default();
        cooldown.hold(Duration::from_secs(30));
        cooldown.refuse(StatusCode::TOO_MANY_REQUESTS, Duration::MAX);
        let made = AtomicUsize::new(0);
        let start = Instant::now();
        let result = run(
            &policy,
            &cooldown,
            || {
                made.fetch_add(1, Ordering::SeqCst);
                async { Ok::<_, Outcome<&'static str>>(()) }
            },
            |_, _| {},
            |_, _| "refused",
        )
        .await;
        assert_eq!(result, Err("refused"));
        assert_eq!(made.load(Ordering::SeqCst), 0);
        assert_eq!(start.elapsed(), Duration::ZERO);
    }

    /// A cooldown that outlasts the budget holds a request back to its end
    /// and leaves the budget to the waits after failures on the way.
    #[tokio::test(start_paused = true)]
    async fn a_cooldown_wait_counts_against_no_budget() {
        let policy = RetryPolicy {
            retries: 3,
            budget: Duration::from_secs(2),
        };
        let cooldown = Cooldown::default();
        cooldown.hold(Duration::from_secs(100));
        let start = tokio::time::Instant::now();
        let made = AtomicUsize::new(0);
        let result = run(
            &policy,
            &cooldown,
            || {
                let first = made.fetch_add(1, Ordering::SeqCst) == 0;
                async move {
                    match first {
                        true => Err(Outcome::transient("timeout")),
                        false => Ok(start.elapsed()),
                    }
                }
            },
            |_, _| {},
            |_, _| "refused",
        )
        .await
        .unwrap();
        assert_eq!(made.load(Ordering::SeqCst), 2);
        let window = Duration::from_millis(100_500)..=Duration::from_millis(101_001);
        assert!(window.contains(&result), "{result:?}");
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
                    |_, _| "refused",
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
