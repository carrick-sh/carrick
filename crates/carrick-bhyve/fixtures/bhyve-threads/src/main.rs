//! M2 Tier-2 fixture: spawn 3 threads, each writes a thread-local and adds it to
//! a shared AtomicUsize, then join. Cross-compiled to x86_64-unknown-linux-musl
//! (static, non-PIE ET_EXEC). Running it under carrick on bhyve exercises
//! clone(CLONE_THREAD) → sibling vCPUs on ONE VM + TLS (fs.base per thread) +
//! the private futex (thread join). Exit 0 iff all three threads ran and the sum
//! is 1+2+3 = 6 — proving real concurrent guest threads on bhyve.
use std::cell::Cell;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

thread_local!(static SLOT: Cell<usize> = const { Cell::new(0) });

fn main() {
    let counter = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();
    for i in 0..3usize {
        let c = Arc::clone(&counter);
        handles.push(std::thread::spawn(move || {
            // Touch the thread-local (per-thread fs.base) then contribute.
            SLOT.with(|s| s.set(i + 1));
            let v = SLOT.with(|s| s.get());
            c.fetch_add(v, Ordering::SeqCst);
        }));
    }
    for h in handles {
        h.join().expect("join");
    }
    let total = counter.load(Ordering::SeqCst);
    if total != 6 {
        eprintln!("threads FAILED: sum={total} (want 6)");
        std::process::exit(1);
    }
    println!("threads ok");
    std::process::exit(0);
}
