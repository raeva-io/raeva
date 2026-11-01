use std::sync::atomic::{AtomicUsize, Ordering};

/// Most threads [`par_map`] runs on.
const MAX_PAR_MAP_THREADS: usize = 8;

/// `f` of each item, in order, computed on up to eight threads, the caller's
/// included. A panic in `f` resumes on the caller.
pub fn par_map<T: Sync, R: Send>(items: &[T], f: impl Fn(&T) -> R + Sync) -> Vec<R> {
    let threads = std::thread::available_parallelism()
        .map_or(1, std::num::NonZero::get)
        .min(MAX_PAR_MAP_THREADS)
        .min(items.len());
    if threads <= 1 {
        return items.iter().map(f).collect();
    }
    let next = AtomicUsize::new(0);
    let work = || {
        let mut done = Vec::new();
        loop {
            let index = next.fetch_add(1, Ordering::Relaxed);
            let Some(item) = items.get(index) else {
                return done;
            };
            done.push((index, f(item)));
        }
    };
    let mut out: Vec<Option<R>> = std::iter::repeat_with(|| None).take(items.len()).collect();
    std::thread::scope(|scope| {
        // Items no worker could be started for are left to the others.
        let workers: Vec<_> = (1..threads)
            .map_while(|_| std::thread::Builder::new().spawn_scoped(scope, work).ok())
            .collect();
        let mut place = |done: Vec<(usize, R)>| {
            for (index, result) in done {
                out[index] = Some(result);
            }
        };
        place(work());
        for worker in workers {
            match worker.join() {
                Ok(done) => place(done),
                Err(panic) => std::panic::resume_unwind(panic),
            }
        }
    });
    out.into_iter()
        .map(|result| result.expect("every item is mapped"))
        .collect()
}
