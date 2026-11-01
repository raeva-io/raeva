//! Log events of work done ahead of its turn, held until the work is used,
//! so the log follows the order the work is used in and leaves out what is
//! never used.

use std::cell::RefCell;
use std::fmt;
use std::future::Future;

use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Dispatch, Event, Metadata, Subscriber};

thread_local! {
    /// The events [`Holds`] holds on this thread for the work it runs.
    static HELD: RefCell<Vec<Entry>> = const { RefCell::new(Vec::new()) };
}

/// `f` of each item, as [`rv_maven_types::par_map`] computes them, with the
/// events each call logged, to be shown when its result is used.
pub fn par_map_held<T: Sync, R: Send>(items: &[T], f: impl Fn(&T) -> R + Sync) -> Vec<(R, Held)> {
    let holds = Holds::default();
    rv_maven_types::par_map(items, |item| {
        tracing::dispatcher::with_default(&holds.0, || {
            let outer = HELD.take();
            let mapped = f(item);
            (mapped, Held(HELD.replace(outer)))
        })
    })
}

/// A subscriber that holds what each piece of work run under it logs, apart
/// from the others and on whatever thread it runs. Creating a subscriber
/// costs a pass over every callsite, so one serves many pieces.
#[derive(Clone)]
pub struct Holds(Dispatch);

impl Default for Holds {
    fn default() -> Self {
        Self(Dispatch::new(Holding {
            outer: tracing::dispatcher::get_default(Dispatch::clone),
        }))
    }
}

impl Holds {
    /// The output of `work`, with what it logged.
    pub async fn hold<F: Future>(&self, work: F) -> (F::Output, Held) {
        let mut events = Vec::new();
        let mut work = std::pin::pin!(work);
        let output = std::future::poll_fn(|cx| {
            let _held = Swapped::new(&mut events);
            tracing::dispatcher::with_default(&self.0, || work.as_mut().poll(cx))
        })
        .await;
        (output, Held(events))
    }
}

/// A piece of work's events, swapped into [`HELD`] until dropped, a panic
/// included.
struct Swapped<'a>(&'a mut Vec<Entry>);

impl<'a> Swapped<'a> {
    fn new(events: &'a mut Vec<Entry>) -> Self {
        HELD.with_borrow_mut(|held| std::mem::swap(held, events));
        Self(events)
    }
}

impl Drop for Swapped<'_> {
    fn drop(&mut self) {
        HELD.with_borrow_mut(|held| std::mem::swap(held, self.0));
    }
}

/// What the work held on this thread has logged so far, taken from its
/// hold. Empty when nothing holds this thread's events.
pub fn take() -> Held {
    Held(HELD.take())
}

/// `f`, logging past any hold on this thread: for what one piece of work
/// does for every later one, such as building a shared client, whose
/// warnings are due whether or not that piece's own are shown.
pub fn unheld<R>(f: impl FnOnce() -> R) -> R {
    let mut outer = None;
    tracing::dispatcher::get_default(|dispatch| {
        let mut dispatch = dispatch;
        while let Some(holding) = dispatch.downcast_ref::<Holding>() {
            dispatch = &holding.outer;
            outer = Some(dispatch.clone());
        }
    });
    match outer {
        Some(outer) => tracing::dispatcher::with_default(&outer, f),
        None => f(),
    }
}

/// How much the work held on this thread has logged so far, for
/// [`logged_since`]. `None` when nothing holds this thread's events.
pub fn mark() -> Option<usize> {
    tracing::dispatcher::get_default(|dispatch| dispatch.is::<Holding>())
        .then(|| HELD.with_borrow(Vec::len))
}

/// Whether the work held on this thread has logged an event at `INFO` or
/// above, or given a warning, since `mark`. True without a mark, as
/// nothing then tells.
pub fn logged_since(mark: Option<usize>) -> bool {
    let Some(mark) = mark else {
        return true;
    };
    HELD.with_borrow(|held| {
        held.iter().skip(mark).any(|entry| match entry {
            Entry::Event(event) => *event.metadata.level() <= tracing::Level::INFO,
            Entry::Give(_) => true,
        })
    })
}

/// Run `give`, which gives a warning only the first time, now or, while
/// this thread's events are held, when they are shown: the first warning
/// shown is then the one given, not the first held.
pub fn when_shown(give: impl FnOnce() + Send + Sync + 'static) {
    give_when_shown(Box::new(give));
}

fn give_when_shown(give: Box<dyn FnOnce() + Send + Sync>) {
    let mut give = Some(give);
    tracing::dispatcher::get_default(|dispatch| {
        if dispatch.is::<Holding>()
            && let Some(give) = give.take()
        {
            keep(Entry::Give(give));
        }
    });
    if let Some(give) = give {
        give();
    }
}

/// Events logged by work done ahead of its turn.
#[must_use]
#[derive(Default)]
pub struct Held(Vec<Entry>);

impl Held {
    /// These events, then those of `then`.
    pub fn and(mut self, then: Held) -> Held {
        self.0.extend(then.0);
        self
    }

    /// Log the events now, to this thread's subscriber: into the hold
    /// around this thread's work, if one holds it.
    pub fn show(self) {
        for entry in self.0 {
            match entry {
                Entry::Event(event) => event.show(),
                Entry::Give(give) => give_when_shown(give),
            }
        }
    }
}

enum Entry {
    Event(HeldEvent),
    Give(Box<dyn FnOnce() + Send + Sync>),
}

struct HeldEvent {
    metadata: &'static Metadata<'static>,
    /// By field index.
    values: Vec<Option<HeldValue>>,
}

enum HeldValue {
    Str(String),
    I64(i64),
    U64(u64),
    Bool(bool),
    Debug(Rendered),
}

/// A value's `Debug` form, rendered when it was logged.
struct Rendered(String);

impl fmt::Debug for Rendered {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl HeldEvent {
    fn show(&self) {
        let debug: Vec<_> = (self.values.iter())
            .map(|value| match value {
                Some(HeldValue::Debug(rendered)) => Some(tracing::field::debug(rendered)),
                _ => None,
            })
            .collect();
        let values: Vec<Option<&dyn tracing::Value>> = (self.values.iter().zip(&debug))
            .map(|(value, debug)| {
                Some(match value.as_ref()? {
                    HeldValue::Str(value) => value as &dyn tracing::Value,
                    HeldValue::I64(value) => value,
                    HeldValue::U64(value) => value,
                    HeldValue::Bool(value) => value,
                    HeldValue::Debug(_) => debug.as_ref()?,
                })
            })
            .collect();
        let fields = self.metadata.fields().value_set_all(&values);
        tracing::dispatcher::get_default(|dispatch| {
            if dispatch.enabled(self.metadata) {
                dispatch.event(&Event::new(self.metadata, &fields));
            }
        });
    }

    fn set(&mut self, field: &Field, value: HeldValue) {
        self.values[field.index()] = Some(value);
    }
}

impl Visit for HeldEvent {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.set(field, HeldValue::Str(value.to_owned()));
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.set(field, HeldValue::I64(value));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.set(field, HeldValue::U64(value));
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.set(field, HeldValue::Bool(value));
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.set(field, HeldValue::Debug(Rendered(format!("{value:?}"))));
    }
}

fn keep(entry: Entry) {
    HELD.with_borrow_mut(|held| held.push(entry));
}

/// The subscriber of held work: the outer one for spans, and a hold for
/// every event the outer one might want.
struct Holding {
    outer: Dispatch,
}

impl Subscriber for Holding {
    fn register_callsite(
        &self,
        metadata: &'static Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        self.outer.register_callsite(metadata)
    }

    fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
        Some(tracing::level_filters::LevelFilter::current())
    }

    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.is_event() || self.outer.enabled(metadata)
    }

    fn event(&self, event: &Event<'_>) {
        let mut held = HeldEvent {
            metadata: event.metadata(),
            values: std::iter::repeat_with(|| None)
                .take(event.metadata().fields().len())
                .collect(),
        };
        event.record(&mut held);
        keep(Entry::Event(held));
    }

    fn new_span(&self, span: &Attributes<'_>) -> Id {
        self.outer.new_span(span)
    }

    fn record(&self, span: &Id, values: &Record<'_>) {
        self.outer.record(span, values);
    }

    fn record_follows_from(&self, span: &Id, follows: &Id) {
        self.outer.record_follows_from(span, follows);
    }

    fn enter(&self, span: &Id) {
        self.outer.enter(span);
    }

    fn exit(&self, span: &Id) {
        self.outer.exit(span);
    }

    fn clone_span(&self, span: &Id) -> Id {
        self.outer.clone_span(span)
    }

    fn try_close(&self, span: Id) -> bool {
        self.outer.try_close(span)
    }
}
