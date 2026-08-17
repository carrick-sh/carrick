//! Whether THIS thread's stage-1 page-table edits are currently EXCLUSIVE.
//!
//! # Why this exists
//!
//! Reclaiming a spare stage-1 sub-table — freeing the page and clearing its
//! parent entry — is a break-before-make change, and reusing that page is only
//! safe when no sibling vCPU can be mid-walk through it or holding a stale
//! cached walk that reaches it. The page-table manager has to know whether that
//! holds, and it cannot work it out for itself.
//!
//! The vCPU run loop is where the answer lives, and it has TWO reasons to say
//! yes for a mapping syscall:
//!
//! - it took the Pause-Modify-Resume transaction, pausing sibling vCPUs and
//!   broadcasting `tlbi vmalle1is` around the edit; or
//! - no peer thread can execute guest code at all, which is why it skipped the
//!   pause in the first place. That population deliberately INCLUDES a sibling
//!   parked in `epoll_wait`, so "none" really does mean no other vCPU is in a
//!   resumable state with a walk cache to go stale.
//!
//! The engine crates cannot ask the runtime — they sit BELOW it — so the marker
//! lives here, in the crate both sides already depend on.
//!
//! # What the engines used to do instead
//!
//! They approximated exclusivity with `Arc::strong_count(&page_tables) > 1`,
//! which is a DIFFERENT POPULATION: live engine handles, not threads that can
//! execute guest code. A single-threaded CPython guest reached this code with
//! THREE live engines and no peer executor, so the proxy said "shared" while
//! the truth was "exclusive", reclaim never ran, and each
//! `mmap(MAP_SHARED, fd)` leaked one stage-1 table until the 440-page pool hit
//! `OutOfTables` — surfaced to the guest as "stage-1 page-table pool
//! exhausted" after a few hundred map/unmap cycles, and the crash behind
//! CPython multiprocessing's SemLock/Pool churn.
//!
//! Thread-local, and nesting-aware: a backend can re-enter the authority while
//! a mapping syscall already owns the outer transaction, so ownership is a
//! DEPTH rather than a flag.

use std::cell::Cell;

thread_local! {
    static EXCLUSIVE_DEPTH: Cell<usize> = const { Cell::new(0) };
}

/// Whether the calling thread's stage-1 edits are exclusive, directly or
/// through an outer transaction it re-entered.
#[must_use]
pub fn current_thread_edits_exclusively() -> bool {
    EXCLUSIVE_DEPTH.with(|depth| depth.get() != 0)
}

/// Record that this thread has established (or re-entered) exclusivity.
/// Callers must pair this with [`exit`]; prefer owning it through the runtime's
/// guard rather than calling either function directly.
pub fn enter() {
    EXCLUSIVE_DEPTH.with(|depth| depth.set(depth.get().saturating_add(1)));
}

/// Record that this thread has released one level of exclusivity. Returns the
/// remaining depth so a caller can assert its own nesting.
pub fn exit() -> usize {
    EXCLUSIVE_DEPTH.with(|depth| {
        let current = depth.get();
        debug_assert!(current != 0, "stage-1 exclusivity ownership underflow");
        let remaining = current.saturating_sub(1);
        depth.set(remaining);
        remaining
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ownership has to nest: an inner acquisition that released the marker on
    /// its own drop would tell the page-table manager exclusivity was gone
    /// while the outer transaction still held it.
    #[test]
    fn ownership_nests_and_clears_only_at_the_outermost_release() {
        assert!(!current_thread_edits_exclusively());
        enter();
        assert!(current_thread_edits_exclusively());
        enter();
        assert_eq!(exit(), 1);
        assert!(current_thread_edits_exclusively(), "outer claim still held");
        assert_eq!(exit(), 0);
        assert!(!current_thread_edits_exclusively());
    }
}
